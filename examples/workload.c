/*
 * Disposable demo target for SysCall-DAG.
 * clean  — read files inside the document root
 * attack — also read a harmless decoy and send it over a UDP socket
 * exec   — exec a shell one-liner
 * dummy  — insert extra open/close pairs, then the attack motif
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void read_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return;
    }
    char buf[4096];
    while (read(fd, buf, sizeof buf) > 0) {
    }
    close(fd);
}

static void exfil(const char *path) {
    char buf[4096];
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
    if (strcmp(mode, "clean-alt") == 0) {
        read_file("/guest/www/page.txt");
        read_file("/guest/www/index.html");
    } else {
        read_file("/guest/www/index.html");
        read_file("/guest/www/page.txt");
    }
    int missing = open("/guest/www/missing.txt", O_RDONLY);
    if (missing >= 0) {
        close(missing);
    }
    if (strcmp(mode, "dummy") == 0) {
        for (int i = 0; i < 24; i++) {
            int fd = open("/guest/www/index.html", O_RDONLY);
            if (fd >= 0) {
                close(fd);
            }
        }
    }
    if (strcmp(mode, "attack") == 0 || strcmp(mode, "exfil") == 0
        || strcmp(mode, "dummy") == 0) {
        exfil("/guest/decoy/secret.txt");
    }
    if (strcmp(mode, "exec") == 0) {
        char *args[] = {"/bin/sh", "-c", "echo pwned", NULL};
        execve("/bin/sh", args, NULL);
    }
    return 0;
}
