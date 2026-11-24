/* switch.c - stage 4: MAC learning, forwarding within a VLAN, trunk port, rate limit timer thread */
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
struct mac_table mac_table;
sem_t free_ports;
struct config cfg;

static int stopping;
static pthread_mutex_t stop_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t stop_cond = PTHREAD_COND_INITIALIZER;
static pthread_t rate_tid;

static int enqueue_to_port(struct port *p, struct pkt *pk)
{
    int ok = -1;

    pthread_mutex_lock(&p->lock);
    if (p->up && (p->trunk || p->vlan == pk->f.vlan)) {
        ok = 0;
        pkt_ref(pk);
        if (queue_push(&p->q, pk) < 0)
            pkt_unref(pk);
    }
    pthread_mutex_unlock(&p->lock);
    return ok;
}

static void forward(int from, const struct frame *f)
{
    struct pkt *pk;
    int out = -1;

    if (!is_broadcast(f->dst))
        out = mac_lookup(&mac_table, f->dst);
    if (out == from)
        return;

    pk = pkt_new(f);
    if (pk == NULL) {
        fprintf(stderr, "out of memory, frame dropped\n");
        return;
    }
    if (out < 0 || enqueue_to_port(&ports[out], pk) < 0) {
        for (int i = 0; i < num_ports; i++) {
            if (i != from)
                enqueue_to_port(&ports[i], pk);
        }
    }
    pkt_unref(pk);
}

static int set_frame_vlan(struct port *p, struct frame *f)
{
    int trunk, vlan;

    pthread_mutex_lock(&p->lock);
    trunk = p->trunk;
    vlan = p->vlan;
    pthread_mutex_unlock(&p->lock);

    if (!trunk) {
        f->vlan = (uint16_t)vlan;
        return 0;
    }
    if (f->vlan < 1 || f->vlan > 4094)
        return -1;
    return 0;
}

static int learn(int port, const struct frame *f)
{
    char src[18];
    int old_port = -1;
    int r;

    if (is_broadcast(f->src))
        return 0;
    r = mac_learn(&mac_table, f->src, port, &old_port);
    mac_to_str(f->src, src);
    if (r == MAC_MOVED) {
        printf("MAC moved: %s from port %d to port %d\n", src, old_port + 1, port + 1);
        fflush(stdout);
    } else if (r == MAC_VIOLATION) {
        printf("port %d: too many MACs (%s), shutting port down\n", port + 1, src);
        fflush(stdout);
        return -1;
    }
    return 0;
}

static void *sender(void *arg)
{
    struct port *p = arg;

    for (;;) {
        struct pkt *pk = queue_pop(&p->q);
        int r;
        if (pk == NULL)
            break;
        r = write_frame(p->fd, &pk->f);
        pkt_unref(pk);
        if (r < 0) {
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

    for (;;) {
        int r = read_frame(p->fd, &f);
        if (r <= 0)
            break;
        if (set_frame_vlan(p, &f) < 0) {
            printf("port %d: bad vlan %u on trunk, frame dropped\n", p->id + 1, f.vlan);
            continue;
        }
        mac_to_str(f.src, src);
        mac_to_str(f.dst, dst);
        printf("port %d: %s -> %s vlan %u prio %u (%u bytes)\n",
               p->id + 1, src, dst, f.vlan, f.priority, f.length);
        fflush(stdout);
        if (learn(p->id, &f) < 0)
            break;
        forward(p->id, &f);
    }

    pthread_mutex_lock(&p->lock);
    p->up = 0;
    pthread_mutex_unlock(&p->lock);

    queue_close(&p->q);
    pthread_join(p->tx, NULL);
    queue_drain(&p->q);
    close(p->fd);
    mac_remove_port(&mac_table, p->id);

    printf("port %d: host disconnected (%lu frames dropped)\n",
           p->id + 1, queue_dropped(&p->q));
    fflush(stdout);

    pthread_mutex_lock(&ports_lock);
    p->used = 0;
    pthread_mutex_unlock(&ports_lock);
    sem_post(&free_ports);
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

static void release_port(struct port *p)
{
    close(p->fd);
    pthread_mutex_lock(&ports_lock);
    p->used = 0;
    pthread_mutex_unlock(&ports_lock);
    sem_post(&free_ports);
}

static void send_switch_full(int fd)
{
    struct frame f;
    const char *msg = "switch full";

    memset(&f, 0, sizeof f);
    memset(f.dst, 0xff, MAC_LEN);
    f.vlan = 1;
    f.length = (uint16_t)strlen(msg);
    memcpy(f.payload, msg, f.length);
    if (write_frame(fd, &f) < 0)
        perror("send_switch_full");
}

static int wait_for_port(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        perror("clock_gettime");
        return -1;
    }
    ts.tv_sec += cfg.port_wait;
    while (sem_timedwait(&free_ports, &ts) < 0) {
        if (errno == EINTR)
            continue;
        if (errno != ETIMEDOUT)
            perror("sem_timedwait");
        return -1;
    }
    return 0;
}

static int start_port(struct port *p, int fd)
{
    pthread_t rx;

    p->fd = fd;
    queue_reset(&p->q);

    if (pthread_create(&p->tx, NULL, sender, p) != 0) {
        fprintf(stderr, "port %d: cannot create sender\n", p->id + 1);
        release_port(p);
        return -1;
    }

    pthread_mutex_lock(&p->lock);
    p->up = 1;
    pthread_mutex_unlock(&p->lock);

    if (pthread_create(&rx, NULL, receiver, p) != 0) {
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

static void *rate_thread(void *arg)
{
    (void)arg;

    pthread_mutex_lock(&stop_lock);
    while (!stopping) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        int r = pthread_cond_timedwait(&stop_cond, &stop_lock, &ts);
        if (r != 0 && r != ETIMEDOUT)
            break;
        if (stopping)
            break;
        pthread_mutex_unlock(&stop_lock);
        for (int i = 0; i < num_ports; i++)
            queue_refill(&ports[i].q);
        pthread_mutex_lock(&stop_lock);
    }
    pthread_mutex_unlock(&stop_lock);
    return NULL;
}

static void stop_rate_thread(void)
{
    pthread_mutex_lock(&stop_lock);
    stopping = 1;
    pthread_cond_signal(&stop_cond);
    pthread_mutex_unlock(&stop_lock);
    pthread_join(rate_tid, NULL);
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

    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: %s <tcp_port> <num_ports> [config_file]\n", argv[0]);
        return 1;
    }
    num_ports = atoi(argv[2]);
    if (num_ports <= 0 || num_ports > MAX_PORTS) {
        fprintf(stderr, "num_ports must be between 1 and %d\n", MAX_PORTS);
        return 1;
    }
    config_defaults(&cfg);
    if (argc == 4 && config_load(&cfg, argv[3], num_ports) < 0)
        return 1;

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
        ports[i].vlan = cfg.port_vlan[i];
        ports[i].trunk = (i == cfg.trunk_port);
        if (pthread_mutex_init(&ports[i].lock, NULL) != 0 ||
            queue_init(&ports[i].q, cfg.queue_size, cfg.weights, cfg.rate_limit) != 0) {
            fprintf(stderr, "port init failed\n");
            return 1;
        }
    }

    if (sem_init(&free_ports, 0, (unsigned int)num_ports) < 0) {
        perror("sem_init");
        return 1;
    }
    if (mac_table_init(&mac_table, num_ports, cfg.mac_max, cfg.mac_per_port, cfg.mac_age) < 0 ||
        mac_table_start_aging(&mac_table) < 0) {
        fprintf(stderr, "mac table init failed\n");
        return 1;
    }

    if (pthread_create(&rate_tid, NULL, rate_thread, NULL) != 0) {
        fprintf(stderr, "cannot start rate limit thread\n");
        return 1;
    }

    listener = make_listener(atoi(argv[1]));
    if (listener < 0)
        return 1;
    printf("switch listening on port %s with %d ports\n", argv[1], num_ports);
    fflush(stdout);

    for (;;) {
        int idx;
        int c = accept(listener, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        if (wait_for_port() < 0) {
            printf("switch full, rejecting host\n");
            fflush(stdout);
            send_switch_full(c);
            close(c);
            continue;
        }
        idx = find_free_port();
        if (idx < 0) {
            sem_post(&free_ports);
            close(c);
            continue;
        }
        if (start_port(&ports[idx], c) == 0) {
            printf("host connected on port %d\n", idx + 1);
            fflush(stdout);
        }
    }

    close(listener);
    stop_rate_thread();
    mac_table_stop_aging(&mac_table);
    mac_table_destroy(&mac_table);
    sem_destroy(&free_ports);
    for (int i = 0; i < num_ports; i++) {
        queue_destroy(&ports[i].q);
        pthread_mutex_destroy(&ports[i].lock);
    }
    free(ports);
    return 0;
}
