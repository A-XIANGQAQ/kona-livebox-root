/*
 * rootsvc.c —— 独立于 Android 框架的 root shell 服务（带来源限制）
 *
 * 为什么需要它：Android 框架（system_server）崩溃时 adb 与图形界面都不可用，
 *   这条原生 TCP 通道不依赖框架，是那时唯一的入口。
 *
 * 加固点：
 *   1) 拒绝来源地址等于「本机自己的 IP」或 127.0.0.1 的连接
 *      —— 本机进程连过来，源地址必然是自己，一律挡掉；从电脑连是外部地址，照常可用
 *      这一条很关键：否则设备上任何一个 App 连 127.0.0.1 就能直接拿到 root
 *   2) 可选令牌：若存在 <RS_PREFIX>/rshell.token，客户端第一行必须与之相同（默认不开）
 *   3) 所有接受/拒绝都写 root.log
 *
 * 编译：clang -O2 -o rootsvc rootsvc.c
 * 定制：改下面两个宏（或编译时 -DRS_PORT=xxxx -DRS_PREFIX=\"...\"）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>

#ifndef RS_PORT
#define RS_PORT      9999
#endif
#ifndef RS_PREFIX
#define RS_PREFIX    "/mnt/vendor/persist/ubiot"   /* 改成你机器的 persist 目录 */
#endif
#define RS_LOG       RS_PREFIX "/root.log"
#define RS_TOKEN     RS_PREFIX "/rshell.token"
#define RS_LOG_MAX   (512 * 1024)
#define RS_MAX_LOCAL 32

static uint32_t local_addrs[RS_MAX_LOCAL];
static int local_cnt;

static void logmsg(const char *fmt, ...)
{
    FILE *f = fopen(RS_LOG, "a");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    if (ftell(f) > RS_LOG_MAX) { fclose(f); f = fopen(RS_LOG, "w"); if (!f) return; }
    time_t t = time(NULL);
    struct tm tm; localtime_r(&t, &tm);
    fprintf(f, "%04d-%02d-%02d %02d:%02d:%02d ", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static void collect_local_addrs(void)
{
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return;
    for (struct ifaddrs *p = ifa; p && local_cnt < RS_MAX_LOCAL; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        uint32_t a = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
        local_addrs[local_cnt++] = a;
    }
    freeifaddrs(ifa);
}

static int is_local_source(uint32_t addr)
{
    if (addr == htonl(INADDR_LOOPBACK)) return 1;
    for (int i = 0; i < local_cnt; i++)
        if (local_addrs[i] == addr) return 1;
    return 0;
}

/* 令牌校验：文件不存在则跳过；返回 0 放行、-1 拒绝 */
static int check_token(int fd)
{
    FILE *tf = fopen(RS_TOKEN, "r");
    if (!tf) return 0;
    char want[128] = {0};
    if (!fgets(want, sizeof want, tf)) { fclose(tf); return 0; }
    fclose(tf);
    char *nl = strchr(want, '\n'); if (nl) *nl = 0;
    if (!want[0]) return 0;

    char got[128] = {0};
    ssize_t n = read(fd, got, sizeof got - 1);
    if (n <= 0) return -1;
    char *g = strchr(got, '\n'); if (g) *g = 0;
    if (strcmp(got, want) != 0) return -1;

    ssize_t w = write(fd, "ok\n", 3); (void)w;
    return 0;
}

int main(void)
{
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    collect_local_addrs();

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { logmsg("rootsvc: socket 失败 %s", strerror(errno)); return 1; }
    int on = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(RS_PORT);

    if (bind(srv, (struct sockaddr *)&sa, sizeof sa) < 0) {
        logmsg("rootsvc: bind %d 失败（已在运行？）%s", RS_PORT, strerror(errno));
        return 1;
    }
    listen(srv, 8);
    logmsg("rootsvc v2 启动 端口=%d 本机地址数=%d 令牌=%s",
           RS_PORT, local_cnt, access(RS_TOKEN, R_OK) == 0 ? "已启用" : "未启用");

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        int c = accept(srv, (struct sockaddr *)&peer, &plen);
        if (c < 0) { if (errno == EINTR) continue; sleep(1); continue; }

        char ip[64];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);

        if (is_local_source(peer.sin_addr.s_addr)) {
            logmsg("拒绝本机来源 %s（有进程试图绕过 su 白名单直连 root shell）", ip);
            const char *msg = "rootsvc: 本机来源被拒绝（请从电脑连接）\n";
            ssize_t w = write(c, msg, strlen(msg)); (void)w;
            close(c);
            continue;
        }

        if (check_token(c) != 0) {
            logmsg("拒绝 %s（令牌不匹配）", ip);
            const char *msg = "rootsvc: 令牌错误\n";
            ssize_t w = write(c, msg, strlen(msg)); (void)w;
            close(c);
            continue;
        }

        logmsg("接受来自 %s 的连接", ip);

        pid_t p = fork();
        if (p == 0) {
            setsid();
            dup2(c, 0); dup2(c, 1); dup2(c, 2);
            if (c > 2) close(c);
            signal(SIGCHLD, SIG_DFL);
            setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin:/vendor/bin", 1);
            setenv("HOME", "/data/local/tmp", 1);
            setenv("TERM", "xterm", 1);
            char *argv[] = { (char *)"sh", (char *)"-i", NULL };
            execv("/system/bin/sh", argv);
            _exit(127);
        }
        close(c);
    }
    return 0;
}
