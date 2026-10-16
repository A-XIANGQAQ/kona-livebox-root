/*
 * rsprop.c (v5) —— 运行时改写系统属性，含只读的 ro.*
 *
 * 为什么需要这么绕：
 *   bionic 把属性区 mmap 成只读，__system_property_update() 一写就 SIGSEGV；
 *   而事后 mprotect 加写权限会被内核拒绝（EPERM，只读 fd 建立的映射不允许提权）。
 * 所以：
 *   1. 用 __system_property_find() 拿到 prop_info 指针（省去解析 trie）
 *   2. 从 /proc/self/maps 反查它属于哪个属性区文件、偏移多少
 *   3. 自己 O_RDWR 打开该文件、mmap 成可写（MAP_SHARED，同一批物理页）
 *   4. 按偏移原地改写值，并按 bionic 的 seqlock 协议递增 serial
 *
 * 只改运行时内存（映射是共享的，其它进程立刻能看到），不落盘；
 * 属性只存在于运行时内存，重启即复原。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sched.h>
#include <sys/mman.h>

typedef void *(*find_t)(const char *);
typedef int (*get_t)(const char *, char *);

static find_t p_find;
static get_t p_get;

static void load(void)
{
    void *h = dlopen("libc.so", RTLD_NOW);
    if (!h) h = RTLD_DEFAULT;
    p_find = (find_t)dlsym(h, "__system_property_find");
    p_get = (get_t)dlsym(h, "__system_property_get");
    if (!p_find || !p_get) {
        fprintf(stderr, "rsprop: missing __system_property_find/get\n");
        exit(2);
    }
}

/* 在 /proc/self/maps 里找到包含 addr 的那段映射，返回文件路径与段起始地址 */
static int find_mapping(void *addr, char *path_out, size_t path_len,
                        unsigned long *start_out, unsigned long *len_out)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;

    char line[1024];
    unsigned long a = (unsigned long)addr;
    int found = 0;

    while (fgets(line, sizeof line, f)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;
        if (a < start || a >= end) continue;

        char *p = strchr(line, '/');
        if (!p) continue;
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;

        snprintf(path_out, path_len, "%s", p);
        *start_out = start;
        *len_out = end - start;
        found = 1;
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

/* 按 bionic 的 prop_info 短值布局原地改写 */
static int force_update(void *pi, const char *value)
{
    char path[512] = {0};
    unsigned long start = 0, len = 0;
    if (find_mapping(pi, path, sizeof path, &start, &len) != 0) {
        fprintf(stderr, "rsprop: cannot locate mapping for prop_info\n");
        return -1;
    }
    if (strncmp(path, "/dev/__properties__/", 20) != 0) {
        fprintf(stderr, "rsprop: unexpected mapping: %s\n", path);
        return -1;
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "rsprop: open(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }
    void *base = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        fprintf(stderr, "rsprop: mmap(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }

    unsigned long off = (unsigned long)pi - start;
    volatile uint32_t *serial = (volatile uint32_t *)((char *)base + off);
    volatile char *val = (volatile char *)((char *)base + off + 4);  /* prop_info: serial 之后就是 value */

    size_t vlen = strlen(value);
    if (vlen > 91) {
        fprintf(stderr, "rsprop: value too long (%zu)\n", vlen);
        munmap(base, len);
        return -1;
    }

    /* seqlock 协议：置脏位 → 写值 → serial 前进 2。
     * 必须保证写值与 serial 的顺序不被编译器/CPU 重排，否则读端会看到半写状态。 */
    for (int i = 0; i < 1000; i++) {
        uint32_t cur = *serial;
        if (cur & 1u) { sched_yield(); continue; }
        *serial = cur | 1u;
        __sync_synchronize();                       /* 脏位先落地 */
        for (size_t k = 0; k < vlen; k++)
            ((volatile char *)val)[k] = value[k];
        ((volatile char *)val)[vlen] = '\0';
        __sync_synchronize();                       /* 值写完再放行 */
        *serial = cur + 2u;
        break;
    }
    munmap(base, len);
    return 0;
}

static void show(const char *name)
{
    char buf[128] = {0};
    if (p_get(name, buf) > 0)
        printf("%s = %s\n", name, buf);
    else
        printf("%s = (unset)\n", name);
}

static int setone(const char *name, const char *value)
{
    char buf[128] = {0};

    void *pi = p_find(name);
    if (!pi) {
        fprintf(stderr, "[skip] no such property: %s\n", name);
        return 1;
    }
    if (force_update(pi, value) != 0) {
        fprintf(stderr, "[FAIL] %s write error\n", name);
        return 1;
    }
    p_get(name, buf);
    if (strcmp(buf, value) != 0) {
        fprintf(stderr, "[FAIL] %s -> %s (readback=%s)\n", name, value, buf);
        return 1;
    }
    printf("[OK] %s = %s\n", name, buf);
    return 0;
}

int main(int argc, char **argv)
{
    load();

    if (argc == 1) {
        const char *keys[] = {
            "ro.product.model", "ro.product.brand", "ro.product.manufacturer",
            "ro.product.device", "ro.product.name", "ro.product.board",
            "ro.build.fingerprint", "ro.build.product", "ro.hardware",
            "ro.product.vendor.model", "ro.product.system.model", "ro.product.odm.model",
            "ro.product.vendor.brand", "ro.product.system.brand", "ro.product.vendor.device",
            "ro.build.version.sdk", "ro.build.version.release", NULL
        };
        for (int i = 0; keys[i]; i++) show(keys[i]);
        return 0;
    }

    if (strcmp(argv[1], "-f") == 0 && argc == 3) {
        FILE *f = fopen(argv[2], "r");
        if (!f) { perror("fopen"); return 1; }
        char line[512];
        int bad = 0;
        while (fgets(line, sizeof line, f)) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            if (!line[0] || line[0] == '#') continue;
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = 0;
            bad += setone(line, eq + 1);
        }
        fclose(f);
        return bad ? 1 : 0;
    }

    if (argc == 2) { show(argv[1]); return 0; }
    if (argc == 3) return setone(argv[1], argv[2]);

    fprintf(stderr, "usage: %s [name [value]] | -f <file>\n", argv[0]);
    return 2;
}
