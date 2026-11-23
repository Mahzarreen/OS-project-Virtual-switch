/* switch.c - stage 2: receiver threads queue frames, a sender thread per port writes them out */
#define _GNU_SOURCE
#include "switch.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct port *ports;
int num_ports;
pthread_mutex_t ports_lock = PTHREAD_MUTEX_INITIALIZER;

static void enqueue_to_port(struct port *p, struct pkt *pk)
{
    pthread_mutex_lock(&p->lock);
    if (p->up) 
    {
        pkt_ref(pk);
        if (queue_push(&p->q, pk) < 0)
        {
            pkt_unref(pk);
        }
    }
    pthread_mutex_unlock(&p->lock);
}

static void forward(int from, const struct frame *f)
{
    struct pkt *pk = pkt_new(f);
    if (pk == NULL) 
    {
        fprintf(stderr, "out of memory, frame dropped\n");
        return;
    }
    for (int i = 0; i < num_ports; i++) 
    {
        if (i != from)
        {
            enqueue_to_port(&ports[i], pk);
        }
    }
    pkt_unref(pk);
}

static void *sender(void *arg)
{
    struct port *p = arg;

    for (;;) 
    {
        struct pkt *pk = queue_pop(&p->q);
        int r;
        if (pk == NULL)
        {
            break;
        }
        r = write_frame(p->fd, &pk->f);
        pkt_unref(pk);
        if (r < 0) 
        {
            fprintf(stderr, "port %d: write failed: %s\n", p->id + 1, strerror(errno));
            shutdown(p->fd, SHUT_RDWR);
            break;
        }
    }
    return NULL;
}

static void *receiver(void *arg)
{
    struct port *p = arg;
    struct frame f;
    char src[18], dst[18];
    for (;;) 
    {
        int r = read_frame(p->fd, &f);
        if (r <= 0)
        {
            break;
        }
        mac_to_str(f.src, src);
        mac_to_str(f.dst, dst);
        printf("port %d: %s -> %s (%u bytes)\n", p->id + 1, src, dst, f.length);
        fflush(stdout);
        forward(p->id, &f);
    }

    pthread_mutex_lock(&p->lock);
    p->up = 0;
    pthread_mutex_unlock(&p->lock);
    queue_close(&p->q);
    pthread_join(p->tx, NULL);
    queue_drain(&p->q);
    close(p->fd);

    printf("port %d: host disconnected (%lu frames dropped)\n",p->id + 1, queue_dropped(&p->q));
    fflush(stdout);
    pthread_mutex_lock(&ports_lock);
    p->used = 0;
    pthread_mutex_unlock(&ports_lock);
    return NULL;
}

static int find_free_port(void)
{
    int found = -1;
    pthread_mutex_lock(&ports_lock);
    for (int i = 0; i < num_ports; i++)
    {
        if (!ports[i].used) 
        {
            ports[i].used = 1;
            found = i;
            break;
        }
    }
    pthread_mutex_unlock(&ports_lock);
    return found;
}

static void release_port(struct port *p)
{
    close(p->fd);
    pthread_mutex_lock(&ports_lock);
    p->used = 0;
    pthread_mutex_unlock(&ports_lock);
}

static int start_port(struct port *p, int fd)
{
    pthread_t rx;

    p->fd = fd;
    queue_reset(&p->q);

    if (pthread_create(&p->tx, NULL, sender, p) != 0) 
    {
        fprintf(stderr, "port %d: cannot create sender\n", p->id + 1);
        release_port(p);
        return -1;
    }

    pthread_mutex_lock(&p->lock);
    p->up = 1;
    pthread_mutex_unlock(&p->lock);

    if (pthread_create(&rx, NULL, receiver, p) != 0) 
    {
        fprintf(stderr, "port %d: cannot create receiver\n", p->id + 1);
        pthread_mutex_lock(&p->lock);
        p->up = 0;
        pthread_mutex_unlock(&p->lock);
        queue_close(&p->q);
        pthread_join(p->tx, NULL);
        queue_drain(&p->q);
        release_port(p);
        return -1;
    }
    pthread_detach(rx);
    return 0;
}

static int make_listener(int tcp_port)
{
    struct sockaddr_in addr;
    int one = 1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) 
    {
        perror("socket");
        return -1;
    }
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0) 
    {
        perror("setsockopt");
        close(s);
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)tcp_port);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) 
    {
        perror("bind");
        close(s);
        return -1;
    }
    if (listen(s, 16) < 0) 
    {
        perror("listen");
        close(s);
        return -1;
    }
    return s;
}

int main(int argc, char *argv[])
{
    int listener;
    if (argc != 3) 
    {
        fprintf(stderr, "usage: %s <tcp_port> <num_ports>\n", argv[0]);
        return 1;
    }
    num_ports = atoi(argv[2]);
    if (num_ports <= 0) 
    {
        fprintf(stderr, "num_ports must be positive\n");
        return 1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) 
    {
        perror("signal");
        return 1;
    }

    ports = calloc((size_t)num_ports, sizeof *ports);
    if (ports == NULL) 
    {
        perror("calloc");
        return 1;
    }
    for (int i = 0; i < num_ports; i++) 
    {
        ports[i].id = i;
        ports[i].fd = -1;
        if (pthread_mutex_init(&ports[i].lock, NULL) != 0 || queue_init(&ports[i].q, QUEUE_CAP) != 0) 
        {
            fprintf(stderr, "port init failed\n");
            return 1;
        }
    }

    listener = make_listener(atoi(argv[1]));
    if (listener < 0)
    {
        return 1;
    }
    printf("switch listening on port %s with %d ports\n", argv[1], num_ports);
    fflush(stdout);

    for (;;) 
    {
        int idx;
        int c = accept(listener, NULL, NULL);
        if (c < 0) 
        {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        idx = find_free_port();
        if (idx < 0) 
        {
            printf("no free port, closing connection\n");
            close(c);
            continue;
        }
        if (start_port(&ports[idx], c) == 0) 
        {
            printf("host connected on port %d\n", idx + 1);
            fflush(stdout);
        }
    }

    close(listener);
    for (int i = 0; i < num_ports; i++) 
    {
        queue_destroy(&ports[i].q);
        pthread_mutex_destroy(&ports[i].lock);
    }
    free(ports);
    return 0;
}
