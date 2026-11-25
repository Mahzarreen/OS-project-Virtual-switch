/* swctl.c - admin tool: sends a command to the switch over a UNIX socket, or shows live stats from shared memory */
#define _GNU_SOURCE
#include "admin.h"
#include "stats.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <command>\n"
            "  show mac | show ports | clear mac\n"
            "  shutdown <port> | up <port>\n"
            "  vlan <port> <vlan>\n"
            "  mirror <port> <sniffer_port>   (sniffer_port 0 stops mirroring)\n"
            "  stats [--watch]\n", prog);
}

static void print_stats(struct switch_stats *s)
{
    struct switch_stats copy;

    pthread_mutex_lock(&s->lock);
    copy.num_ports = s->num_ports;
    memcpy(copy.port, s->port, sizeof copy.port);
    pthread_mutex_unlock(&s->lock);

    printf("%-5s %10s %10s %10s %10s\n", "PORT", "IN", "OUT", "DROPPED", "MIRRORED");
    for (int i = 0; i < copy.num_ports && i < MAX_PORTS; i++)
        printf("%-5d %10lu %10lu %10lu %10lu\n", i + 1,
               copy.port[i].in, copy.port[i].out, copy.port[i].dropped, copy.port[i].mirrored);
}

static int do_stats(int watch)
{
    struct switch_stats *s = stats_open();
    if (s == NULL) {
        fprintf(stderr, "cannot open shared memory, is the switch running?\n");
        return 1;
    }
    if (!watch) {
        print_stats(s);
        stats_close(s);
        return 0;
    }
    for (;;) {
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
        printf("\033[H\033[J");
        print_stats(s);
        printf("\npress Enter to quit\n");
        fflush(stdout);
        int r = poll(&pfd, 1, 1000);
        if (r < 0 && errno != EINTR) {
            perror("poll");
            break;
        }
        if (r > 0)
            break;
    }
    stats_close(s);
    return 0;
}

static int send_command(const char *cmd)
{
    struct sockaddr_un addr;
    char buf[4096];
    ssize_t n;
    int s = socket(AF_UNIX, SOCK_STREAM, 0);

    if (s < 0) {
        perror("socket");
        return 1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ADMIN_SOCKET, sizeof addr.sun_path - 1);
    if (connect(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("connect (is the switch running?)");
        close(s);
        return 1;
    }

    size_t len = strlen(cmd);
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(s, cmd + done, len - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            perror("write");
            close(s);
            return 1;
        }
        done += (size_t)w;
    }
    if (shutdown(s, SHUT_WR) < 0)
        perror("shutdown");

    while ((n = read(s, buf, sizeof buf)) != 0) {
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("read");
            break;
        }
        fwrite(buf, 1, (size_t)n, stdout);
    }
    close(s);
    return 0;
}

int main(int argc, char *argv[])
{
    char cmd[256] = "";

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "stats") == 0)
        return do_stats(argc > 2 && strcmp(argv[2], "--watch") == 0);

    for (int i = 1; i < argc; i++) {
        if (strlen(cmd) + strlen(argv[i]) + 2 > sizeof cmd) {
            fprintf(stderr, "command too long\n");
            return 1;
        }
        if (i > 1)
            strcat(cmd, " ");
        strcat(cmd, argv[i]);
    }
    strcat(cmd, "\n");
    return send_command(cmd);
}
