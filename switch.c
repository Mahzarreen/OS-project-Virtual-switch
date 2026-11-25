/* switch.c - the switch: forwarding, VLANs, mirroring, port lifecycle, signal thread and clean shutdown */
#define _GNU_SOURCE
#include "switch.h"
#include "stats.h"
#include "admin.h"
#include "logger.h"

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
static pthread_cond_t port_done = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t cfg_lock = PTHREAD_MUTEX_INITIALIZER;
static int running = 1;
static pthread_mutex_t run_lock = PTHREAD_MUTEX_INITIALIZER;
static int listener = -1;
static pthread_t sig_tid;
static const char *config_path;

static void mirror_push(int sniffer, int from, struct pkt *pk)
{
    struct port *s = &ports[sniffer];

    pthread_mutex_lock(&s->lock);
    if (s->up) {
        pkt_ref(pk);
        if (queue_push(&s->q, pk) < 0) {
            pkt_unref(pk);
            stats_inc(sniffer, STAT_DROPPED);
        } else {
            stats_inc(from, STAT_MIRRORED);
        }
    }
    pthread_mutex_unlock(&s->lock);
}

static int mirror_target(struct port *p)
{
    int m;
    pthread_mutex_lock(&p->lock);
    m = p->mirror_to;
    pthread_mutex_unlock(&p->lock);
    return m;
}

static int enqueue_to_port(struct port *p, struct pkt *pk)
{
    int ok = -1;
    int mirror = -1;

    pthread_mutex_lock(&p->lock);
    if (p->up && (p->trunk || p->vlan == pk->f.vlan)) {
        ok = 0;
        mirror = p->mirror_to;
        pkt_ref(pk);
        if (queue_push(&p->q, pk) < 0) {
            pkt_unref(pk);
            stats_inc(p->id, STAT_DROPPED);
        }
    }
    pthread_mutex_unlock(&p->lock);

    if (mirror >= 0)
        mirror_push(mirror, p->id, pk);
    return ok;
}

static void forward(int from, struct pkt *pk)
{
    int out = -1;

    if (!is_broadcast(pk->f.dst))
        out = mac_lookup(&mac_table, pk->f.dst);
    if (out == from)
        return;

    if (out < 0 || enqueue_to_port(&ports[out], pk) < 0) {
        for (int i = 0; i < num_ports; i++) {
            if (i != from)
                enqueue_to_port(&ports[i], pk);
        }
    }
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
        log_msg("MAC moved: %s from port %d to port %d", src, old_port + 1, port + 1);
    } else if (r == MAC_VIOLATION) {
        log_msg("port %d: too many MACs (%s), port disabled", port + 1, src);
        return -1;
    }
    return 0;
}

static void disable_port(struct port *p)
{
    pthread_mutex_lock(&ports_lock);
    pthread_mutex_lock(&p->lock);
    p->disabled = 1;
    pthread_mutex_unlock(&p->lock);
    pthread_mutex_unlock(&ports_lock);
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
            log_msg("port %d: write failed: %s", p->id + 1, strerror(errno));
            shutdown(p->fd, SHUT_RDWR);
            break;
        }
        stats_inc(p->id, STAT_OUT);
    }
    return NULL;
}

static void *receiver(void *arg)
{
    struct port *p = arg;
    struct frame f;
    char src[18], dst[18];

    for (;;) {
        struct pkt *pk;
        int mirror;
        int r = read_frame(p->fd, &f);
        if (r <= 0)
            break;
        stats_inc(p->id, STAT_IN);
        if (set_frame_vlan(p, &f) < 0) {
            log_msg("port %d: bad vlan %u on trunk, frame dropped", p->id + 1, f.vlan);
            continue;
        }
        mac_to_str(f.src, src);
        mac_to_str(f.dst, dst);
        log_msg("port %d: %s -> %s vlan %u prio %u (%u bytes)",
               p->id + 1, src, dst, f.vlan, f.priority, f.length);
        if (learn(p->id, &f) < 0) {
            disable_port(p);
            break;
        }

        pk = pkt_new(&f);
        if (pk == NULL) {
            log_msg("out of memory, frame dropped");
            continue;
        }
        mirror = mirror_target(p);
        if (mirror >= 0)
            mirror_push(mirror, p->id, pk);
        forward(p->id, pk);
        pkt_unref(pk);
    }

    pthread_mutex_lock(&p->lock);
    p->up = 0;
    pthread_mutex_unlock(&p->lock);

    queue_close(&p->q);
    pthread_join(p->tx, NULL);
    queue_drain(&p->q);
    close(p->fd);
    mac_remove_port(&mac_table, p->id);

    log_msg("port %d: host disconnected (%lu frames dropped)",
           p->id + 1, queue_dropped(&p->q));

    pthread_mutex_lock(&ports_lock);
    p->state = PORT_DONE;
    pthread_cond_broadcast(&port_done);
    pthread_mutex_unlock(&ports_lock);
    sem_post(&free_ports);
    return NULL;
}

static int find_free_port(void)
{
    int found = -1;
    int was_done = 0;

    pthread_mutex_lock(&ports_lock);
    for (int i = 0; i < num_ports; i++) {
        if (!ports[i].disabled && ports[i].state != PORT_BUSY) {
            was_done = (ports[i].state == PORT_DONE);
            ports[i].state = PORT_BUSY;
            found = i;
            break;
        }
    }
    pthread_mutex_unlock(&ports_lock);

    if (found >= 0 && was_done)
        pthread_join(ports[found].rx, NULL);
    return found;
}

static void release_port(struct port *p)
{
    close(p->fd);
    pthread_mutex_lock(&ports_lock);
    p->state = PORT_FREE;
    pthread_cond_broadcast(&port_done);
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
    pthread_mutex_lock(&cfg_lock);
    ts.tv_sec += cfg.port_wait;
    pthread_mutex_unlock(&cfg_lock);
    while (sem_timedwait(&free_ports, &ts) < 0) {
        if (errno == EINTR)
            continue;
        if (errno != ETIMEDOUT)
            perror("sem_timedwait");
        return -1;
    }
    return 0;
}

static void stop_sender(struct port *p)
{
    pthread_mutex_lock(&p->lock);
    p->up = 0;
    pthread_mutex_unlock(&p->lock);
    queue_close(&p->q);
    pthread_join(p->tx, NULL);
    queue_drain(&p->q);
}

static int start_port(struct port *p, int fd)
{
    int r;

    p->fd = fd;
    queue_reset(&p->q);

    pthread_mutex_lock(&p->lock);
    if (p->disabled) {
        pthread_mutex_unlock(&p->lock);
        release_port(p);
        return -1;
    }
    p->up = 1;
    pthread_mutex_unlock(&p->lock);

    if (pthread_create(&p->tx, NULL, sender, p) != 0) {
        fprintf(stderr, "port %d: cannot create sender\n", p->id + 1);
        pthread_mutex_lock(&p->lock);
        p->up = 0;
        pthread_mutex_unlock(&p->lock);
        release_port(p);
        return -1;
    }

    pthread_mutex_lock(&ports_lock);
    r = pthread_create(&p->rx, NULL, receiver, p);
    pthread_mutex_unlock(&ports_lock);
    if (r != 0) {
        fprintf(stderr, "port %d: cannot create receiver\n", p->id + 1);
        stop_sender(p);
        release_port(p);
        return -1;
    }
    return 0;
}

static void stop_port(struct port *p)
{
    pthread_mutex_lock(&ports_lock);
    pthread_mutex_lock(&p->lock);
    p->disabled = 1;
    if (p->up)
        shutdown(p->fd, SHUT_RDWR);
    pthread_mutex_unlock(&p->lock);

    while (p->state == PORT_BUSY)
        pthread_cond_wait(&port_done, &ports_lock);
    if (p->state == PORT_DONE) {
        pthread_join(p->rx, NULL);
        p->state = PORT_FREE;
    }
    pthread_mutex_unlock(&ports_lock);
}

int port_shutdown(int idx)
{
    if (idx < 0 || idx >= num_ports)
        return -1;
    stop_port(&ports[idx]);
    log_msg("port %d shut down by admin", idx + 1);
    return 0;
}

int port_enable(int idx)
{
    if (idx < 0 || idx >= num_ports)
        return -1;
    pthread_mutex_lock(&ports_lock);
    pthread_mutex_lock(&ports[idx].lock);
    ports[idx].disabled = 0;
    pthread_mutex_unlock(&ports[idx].lock);
    pthread_mutex_unlock(&ports_lock);
    log_msg("port %d enabled by admin", idx + 1);
    return 0;
}

int port_set_vlan(int idx, int vlan)
{
    if (idx < 0 || idx >= num_ports || vlan < 1 || vlan > 4094)
        return -1;
    pthread_mutex_lock(&ports[idx].lock);
    ports[idx].vlan = vlan;
    pthread_mutex_unlock(&ports[idx].lock);
    mac_remove_port(&mac_table, idx);
    log_msg("port %d moved to vlan %d", idx + 1, vlan);
    return 0;
}

int port_set_mirror(int idx, int target)
{
    if (idx < 0 || idx >= num_ports || target < -1 || target >= num_ports || target == idx)
        return -1;
    pthread_mutex_lock(&ports[idx].lock);
    ports[idx].mirror_to = target;
    pthread_mutex_unlock(&ports[idx].lock);
    return 0;
}

void port_show(FILE *out)
{
    fprintf(out, "%-5s %-9s %-6s %-6s %s\n", "PORT", "STATE", "VLAN", "TRUNK", "MIRROR");
    pthread_mutex_lock(&ports_lock);
    for (int i = 0; i < num_ports; i++) {
        struct port *p = &ports[i];
        const char *state;
        int vlan, trunk, mirror;

        pthread_mutex_lock(&p->lock);
        if (p->disabled)
            state = "disabled";
        else if (p->up)
            state = "up";
        else
            state = "free";
        vlan = p->vlan;
        trunk = p->trunk;
        mirror = p->mirror_to;
        pthread_mutex_unlock(&p->lock);

        fprintf(out, "%-5d %-9s %-6d %-6s ", i + 1, state, vlan, trunk ? "yes" : "no");
        if (mirror >= 0)
            fprintf(out, "-> %d\n", mirror + 1);
        else
            fprintf(out, "-\n");
    }
    pthread_mutex_unlock(&ports_lock);
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

static int is_running(void)
{
    int r;
    pthread_mutex_lock(&run_lock);
    r = running;
    pthread_mutex_unlock(&run_lock);
    return r;
}

static void request_stop(void)
{
    pthread_mutex_lock(&run_lock);
    running = 0;
    pthread_mutex_unlock(&run_lock);
    shutdown(listener, SHUT_RDWR);
    sem_post(&free_ports);
}

static void reload_config(void)
{
    struct config fresh;

    config_defaults(&fresh);
    if (config_path == NULL) {
        log_msg("SIGHUP: no config file given, nothing to reload");
        return;
    }
    if (config_load(&fresh, config_path, num_ports) < 0) {
        log_msg("SIGHUP: %s has errors, keeping the old config", config_path);
        return;
    }

    pthread_mutex_lock(&cfg_lock);
    if (fresh.queue_size != cfg.queue_size)
        log_msg("SIGHUP: queue_size only changes after a restart");
    fresh.queue_size = cfg.queue_size;
    cfg = fresh;
    pthread_mutex_unlock(&cfg_lock);

    mac_table_set_limits(&mac_table, fresh.mac_max, fresh.mac_per_port, fresh.mac_age);
    for (int i = 0; i < num_ports; i++) {
        struct port *p = &ports[i];
        int changed;

        queue_set_limits(&p->q, fresh.rate_limit, fresh.weights);
        pthread_mutex_lock(&p->lock);
        changed = (p->vlan != fresh.port_vlan[i]) || (p->trunk != (i == fresh.trunk_port));
        p->vlan = fresh.port_vlan[i];
        p->trunk = (i == fresh.trunk_port);
        pthread_mutex_unlock(&p->lock);
        if (changed)
            mac_remove_port(&mac_table, i);
    }
    log_msg("SIGHUP: config reloaded from %s", config_path);
}

static void dump_mac_table(void)
{
    FILE *fp = fopen(MAC_DUMP_FILE, "w");
    if (fp == NULL) {
        log_msg("SIGUSR1: cannot open %s: %s", MAC_DUMP_FILE, strerror(errno));
        return;
    }
    mac_dump(&mac_table, fp);
    if (fclose(fp) != 0)
        log_msg("SIGUSR1: error writing %s", MAC_DUMP_FILE);
    else
        log_msg("SIGUSR1: mac table written to %s", MAC_DUMP_FILE);
}

static void *signal_thread(void *arg)
{
    sigset_t *set = arg;

    for (;;) {
        int sig;
        if (sigwait(set, &sig) != 0)
            continue;
        if (sig == SIGINT || sig == SIGTERM) {
            log_msg("got %s, shutting down", sig == SIGINT ? "SIGINT" : "SIGTERM");
            request_stop();
            break;
        } else if (sig == SIGHUP) {
            reload_config();
        } else if (sig == SIGUSR1) {
            dump_mac_table();
        }
    }
    return NULL;
}

static void accept_loop(void)
{
    while (is_running()) {
        int idx;
        int c = accept(listener, NULL, NULL);
        if (c < 0) {
            if (!is_running())
                break;
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            log_msg("accept failed: %s, shutting down", strerror(errno));
            kill(getpid(), SIGTERM);
            break;
        }

        if (wait_for_port() < 0) {
            log_msg("switch full, rejecting host");
            send_switch_full(c);
            close(c);
            continue;
        }
        if (!is_running()) {
            close(c);
            break;
        }
        idx = find_free_port();
        if (idx < 0) {
            sem_post(&free_ports);
            log_msg("no enabled port free, rejecting host");
            send_switch_full(c);
            close(c);
            continue;
        }
        if (start_port(&ports[idx], c) == 0)
            log_msg("host connected on port %d", idx + 1);
    }
}

int main(int argc, char *argv[])
{
    sigset_t set;

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
    if (argc == 4) {
        config_path = argv[3];
        if (config_load(&cfg, config_path, num_ports) < 0)
            return 1;
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        return 1;
    }
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);
    if (signal(SIGINT, SIG_DFL) == SIG_ERR || signal(SIGHUP, SIG_DFL) == SIG_ERR) {
        perror("signal");
        return 1;
    }
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        fprintf(stderr, "pthread_sigmask failed\n");
        return 1;
    }

    if (logger_start(LOG_FILE) < 0)
        return 1;

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
        ports[i].mirror_to = -1;
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
    if (stats_create(num_ports) < 0)
        return 1;

    listener = make_listener(atoi(argv[1]));
    if (listener < 0)
        return 1;
    if (admin_start() < 0)
        return 1;
    if (pthread_create(&rate_tid, NULL, rate_thread, NULL) != 0 ||
        pthread_create(&sig_tid, NULL, signal_thread, &set) != 0) {
        fprintf(stderr, "cannot start threads\n");
        return 1;
    }
    log_msg("switch listening on port %s with %d ports (pid %d)", argv[1], num_ports, (int)getpid());

    accept_loop();

    log_msg("stopping: closing admin socket and all ports");
    close(listener);
    admin_stop();
    for (int i = 0; i < num_ports; i++)
        stop_port(&ports[i]);
    stop_rate_thread();
    mac_table_stop_aging(&mac_table);
    pthread_join(sig_tid, NULL);
    log_msg("switch stopped cleanly");
    logger_stop();

    mac_table_destroy(&mac_table);
    sem_destroy(&free_ports);
    for (int i = 0; i < num_ports; i++) {
        queue_destroy(&ports[i].q);
        pthread_mutex_destroy(&ports[i].lock);
    }
    free(ports);
    stats_destroy();
    return 0;
}
