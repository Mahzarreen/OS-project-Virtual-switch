/* switch.c - stage 1: accepts hosts as ports, one receiver thread per port, floods every frame */
#define _GNU_SOURCE
#include "frame.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct port {
    int id;
    int used;
    int fd;
    pthread_mutex_t lock;
};

static struct port *ports;
static int num_ports;
static pthread_mutex_t ports_lock = PTHREAD_MUTEX_INITIALIZER;

static void flood(int from, const struct frame *f)
{
    for (int i = 0; i < num_ports; i++) {
        if (i == from)
            continue;
        pthread_mutex_lock(&ports[i].lock);
        if (ports[i].fd >= 0 && write_frame(ports[i].fd, f) < 0)
            fprintf(stderr, "port %d: write failed: %s\n", i + 1, strerror(errno));
        pthread_mutex_unlock(&ports[i].lock);
    }
}

static void *receiver(void *arg)
{
    struct port *p = arg;
    struct frame f;
    char src[18], dst[18];
    int fd;

    pthread_mutex_lock(&p->lock);
    fd = p->fd;
    pthread_mutex_unlock(&p->lock);

    for (;;) {
        int r = read_frame(fd, &f);
        if (r <= 0)
            break;
        mac_to_str(f.src, src);
        mac_to_str(f.dst, dst);
        printf("port %d: %s -> %s (%u bytes)\n", p->id + 1, src, dst, f.length);
        fflush(stdout);
        flood(p->id, &f);
    }

    printf("port %d: host disconnected\n", p->id + 1);
    fflush(stdout);

    pthread_mutex_lock(&p->lock);
    close(p->fd);
    p->fd = -1;
    pthread_mutex_unlock(&p->lock);

    pthread_mutex_lock(&ports_lock);
    p->used = 0;
    pthread_mutex_unlock(&ports_lock);
    return NULL;
}

static int find_free_port(void)
{
    int found = -1;
    pthread_mutex_lock(&ports_lock);
    for (int i = 0; i < num_ports; i++) {
        if (!ports[i].used) {
            ports[i].used = 1;
            found = i;
            break;
        }
    }
    pthread_mutex_unlock(&ports_lock);
    return found;
}

static int make_listener(int tcp_port)
{
    struct sockaddr_in addr;
    int one = 1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0) {
        perror("setsockopt");
        close(s);
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)tcp_port);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        close(s);
        return -1;
    }
    if (listen(s, 16) < 0) {
        perror("listen");
        close(s);
        return -1;
    }
    return s;
}

int main(int argc, char *argv[])
{
    int listener;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <tcp_port> <num_ports>\n", argv[0]);
        return 1;
    }
    num_ports = atoi(argv[2]);
    if (num_ports <= 0) {
        fprintf(stderr, "num_ports must be positive\n");
        return 1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    ports = calloc((size_t)num_ports, sizeof *ports);
    if (ports == NULL) {
        perror("calloc");
        return 1;
    }
    for (int i = 0; i < num_ports; i++) {
        ports[i].id = i;
        ports[i].fd = -1;
        if (pthread_mutex_init(&ports[i].lock, NULL) != 0) {
            fprintf(stderr, "mutex init failed\n");
            return 1;
        }
    }

    listener = make_listener(atoi(argv[1]));
    if (listener < 0)
        return 1;
    printf("switch listening on port %s with %d ports\n", argv[1], num_ports);
    fflush(stdout);

    for (;;) {
        pthread_t tid;
        int idx;
        int c = accept(listener, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        idx = find_free_port();
        if (idx < 0) {
            printf("no free port, closing connection\n");
            close(c);
            continue;
        }

        pthread_mutex_lock(&ports[idx].lock);
        ports[idx].fd = c;
        pthread_mutex_unlock(&ports[idx].lock);

        if (pthread_create(&tid, NULL, receiver, &ports[idx]) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            pthread_mutex_lock(&ports[idx].lock);
            close(c);
            ports[idx].fd = -1;
            pthread_mutex_unlock(&ports[idx].lock);
            pthread_mutex_lock(&ports_lock);
            ports[idx].used = 0;
            pthread_mutex_unlock(&ports_lock);
            continue;
        }
        pthread_detach(tid);
        printf("host connected on port %d\n", idx + 1);
        fflush(stdout);
    }

    close(listener);
    for (int i = 0; i < num_ports; i++)
        pthread_mutex_destroy(&ports[i].lock);
    free(ports);
    return 0;
}
