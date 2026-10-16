/*
 * sysctlwrite.c —— 干净地把字符串写进 sysctl（含 NUL 结尾，避免残留尾巴）
 * 用法: sysctlwrite <sysctl 路径> <新值>
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "用法: %s <路径> <值>\n", argv[0]); return 2; }

    int fd = open(argv[1], O_WRONLY);
    if (fd < 0) { fprintf(stderr, "打开 %s 失败: %s\n", argv[1], strerror(errno)); return 1; }

    /* 值 + NUL，保证内核里的字符串在此处终止，不会留下旧值的尾巴 */
    char buf[512];
    size_t n = strlen(argv[2]);
    if (n > sizeof buf - 1) n = sizeof buf - 1;
    memcpy(buf, argv[2], n);
    buf[n] = '\0';

    ssize_t w = write(fd, buf, n + 1);
    close(fd);
    if (w < 0) { fprintf(stderr, "写入失败: %s\n", strerror(errno)); return 1; }

    printf("已写入 %s = %s (%zd 字节)\n", argv[1], argv[2], w);
    return 0;
}
