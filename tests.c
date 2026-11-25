/* tests.c - automatic tests for the virtual switch: ./tests [--tsan | --valgrind] */
#define _GNU_SOURCE
#include "frame.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_RECORDS 4096
#define MAX_HOSTS 16
#define BIG 65536

enum { MODE_NORMAL, MODE_TSAN, MODE_VALGRIND };

struct record {
    char text[64];
    int vlan;
    int prio;
};

struct host {
    int fd;
    uint8_t mac[MAC_LEN];
    int reading;
    int closed;
    int count;
    struct record rec[MAX_RECORDS];
    pthread_t tid;
    pthread_mutex_t lock;
};

struct sw {
    pid_t pid;
    int port;
    int running;
    char dir[64];
    char out[128];
    char conf[128];
    char vglog[128];
};

static int mode = MODE_NORMAL;
static int slow = 1;
static int next_port;
static char here[512];
static char fail_msg[4096];
static struct sw *cur_sw;
static struct host *hosts[MAX_HOSTS];
static int num_hosts;
static uint8_t bcast[MAC_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#define CHECK(cond, ...)                                          \
    do {                                                          \
        if (!(cond)) {                                            \
            snprintf(fail_msg, sizeof fail_msg, __VA_ARGS__);     \
            return -1;                                            \
        }                                                         \
    } while (0)

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
        ;
}

static void mac(const char *s, uint8_t out[MAC_LEN])
{
    if (parse_mac(s, out) < 0)
        memset(out, 0, MAC_LEN);
}

static size_t pack_frame(uint8_t *buf, const uint8_t src[MAC_LEN], const uint8_t dst[MAC_LEN],
                         const char *text, int vlan, int prio)
{
    uint16_t len = (uint16_t)strlen(text);
    uint16_t v = htons(len);
    memcpy(buf, &v, 2);
    memcpy(buf + 2, src, MAC_LEN);
    memcpy(buf + 8, dst, MAC_LEN);
    v = htons((uint16_t)vlan);
    memcpy(buf + 14, &v, 2);
    buf[16] = (uint8_t)prio;
    memcpy(buf + HDR_LEN, text, len);
    return HDR_LEN + len;
}

static int file_has(const char *path, const char *text)
{
    char buf[65536 + 512];
    size_t keep = 0, tlen = strlen(text);
    int found = 0;
    int fd = open(path, O_RDONLY);

    if (fd < 0)
        return 0;
    for (;;) {
        ssize_t r = read(fd, buf + keep, sizeof buf - 1 - keep);
        if (r <= 0)
            break;
        size_t len = keep + (size_t)r;
        buf[len] = '\0';
        if (strstr(buf, text) != NULL) {
            found = 1;
            break;
        }
        keep = tlen < len ? tlen : len;
        memmove(buf, buf + len - keep, keep);
    }
    close(fd);
    return found;
}

static void swctl(char *out, size_t size, const char *args)
{
    char cmd[1024];
    size_t got = 0;
    FILE *fp;

    snprintf(cmd, sizeof cmd, "%s/swctl %s 2>&1", here, args);
    out[0] = '\0';
    fp = popen(cmd, "r");
    if (fp == NULL)
        return;
    while (got < size - 1) {
        size_t n = fread(out + got, 1, size - 1 - got, fp);
        if (n == 0)
            break;
        got += n;
    }
    out[got] = '\0';
    pclose(fp);
}

static int swctl_has(const char *args, const char *text)
{
    char out[BIG];
    swctl(out, sizeof out, args);
    return strstr(out, text) != NULL;
}

static int stats_value(int port, int column)
{
    char out[BIG];
    char *line;
    swctl(out, sizeof out, "stats");
    for (line = strtok(out, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        int p;
        unsigned long v[4];
        if (sscanf(line, "%d %lu %lu %lu %lu", &p, &v[0], &v[1], &v[2], &v[3]) == 5 && p == port)
            return (int)v[column];
    }
    return -1;
}

static int sw_log_has(struct sw *s, const char *text, int seconds)
{
    double end = now() + seconds * slow;
    while (now() < end) {
        if (file_has(s->out, text))
            return 1;
        sleep_ms(50);
    }
    return file_has(s->out, text);
}

static int sw_alive(struct sw *s)
{
    return waitpid(s->pid, NULL, WNOHANG) == 0;
}

static int sw_launch(struct sw *s, int nports, int use_setarch)
{
    char portstr[16], nstr[16], vgarg[160];
    char *argv[16];
    int n = 0;
    struct utsname u;

    snprintf(portstr, sizeof portstr, "%d", s->port);
    snprintf(nstr, sizeof nstr, "%d", nports);
    snprintf(vgarg, sizeof vgarg, "--log-file=%s", s->vglog);

    char sw_path[600], tsan_path[600];
    snprintf(sw_path, sizeof sw_path, "%s/switch", here);
    snprintf(tsan_path, sizeof tsan_path, "%s/switch_tsan", here);

    if (use_setarch && uname(&u) == 0) {
        argv[n++] = "setarch";
        argv[n++] = u.machine;
        argv[n++] = "-R";
    }
    if (mode == MODE_VALGRIND) {
        argv[n++] = "valgrind";
        argv[n++] = "--leak-check=full";
        argv[n++] = vgarg;
    }
    argv[n++] = mode == MODE_TSAN ? tsan_path : sw_path;
    argv[n++] = portstr;
    argv[n++] = nstr;
    if (s->conf[0] != '\0')
        argv[n++] = s->conf;
    argv[n] = NULL;

    s->pid = fork();
    if (s->pid < 0)
        return -1;
    if (s->pid == 0) {
        int fd = open(s->out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || chdir(s->dir) < 0)
            _exit(127);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        signal(SIGINT, SIG_DFL);
        execvp(argv[0], argv);
        _exit(127);
    }

    double end = now() + 5 * slow;
    while (now() < end) {
        if (!sw_alive(s))
            return -1;
        if (file_has(s->out, "switch listening on port"))
            return 0;
        sleep_ms(50);
    }
    return -1;
}

static int sw_start(struct sw *s, int nports, const char *config)
{
    memset(s, 0, sizeof *s);
    s->port = next_port++;
    strcpy(s->dir, "/tmp/vswitch_test_XXXXXX");
    if (mkdtemp(s->dir) == NULL) {
        snprintf(fail_msg, sizeof fail_msg, "mkdtemp failed");
        return -1;
    }
    snprintf(s->out, sizeof s->out, "%s/output.txt", s->dir);
    snprintf(s->vglog, sizeof s->vglog, "%s/valgrind.txt", s->dir);
    if (config != NULL) {
        snprintf(s->conf, sizeof s->conf, "%s/test.conf", s->dir);
        FILE *fp = fopen(s->conf, "w");
        if (fp == NULL)
            return -1;
        fputs(config, fp);
        fclose(fp);
    }
    cur_sw = s;
    s->running = 1;
    if (sw_launch(s, nports, 0) == 0)
        return 0;
    if (mode == MODE_TSAN && file_has(s->out, "unexpected memory mapping") && sw_launch(s, nports, 1) == 0)
        return 0;
    s->running = 0;
    kill(s->pid, SIGKILL);
    waitpid(s->pid, NULL, 0);
    snprintf(fail_msg, sizeof fail_msg, "switch did not start, see %s", s->out);
    return -1;
}

static int sw_stop(struct sw *s)
{
    int status;
    double end;

    if (!s->running)
        return 0;
    s->running = 0;
    kill(s->pid, SIGINT);
    end = now() + 30 * slow;
    while (now() < end) {
        pid_t r = waitpid(s->pid, &status, WNOHANG);
        if (r == s->pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        sleep_ms(50);
    }
    kill(s->pid, SIGKILL);
    waitpid(s->pid, NULL, 0);
    return -1;
}

static void *host_reader(void *arg)
{
    struct host *h = arg;
    struct frame f;

    while (read_frame(h->fd, &f) > 0) {
        pthread_mutex_lock(&h->lock);
        if (h->count < MAX_RECORDS) {
            struct record *r = &h->rec[h->count++];
            int n = f.length < sizeof r->text - 1 ? f.length : (int)sizeof r->text - 1;
            memcpy(r->text, f.payload, (size_t)n);
            r->text[n] = '\0';
            r->vlan = f.vlan;
            r->prio = f.priority;
        }
        pthread_mutex_unlock(&h->lock);
    }
    pthread_mutex_lock(&h->lock);
    h->closed = 1;
    pthread_mutex_unlock(&h->lock);
    return NULL;
}

static int connect_switch(struct sw *s)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)s->port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static struct host *host_open(struct sw *s, const char *m, int reading)
{
    struct host *h = calloc(1, sizeof *h);
    if (h == NULL || num_hosts == MAX_HOSTS)
        return NULL;
    h->fd = connect_switch(s);
    if (h->fd < 0) {
        free(h);
        return NULL;
    }
    mac(m, h->mac);
    h->reading = reading;
    pthread_mutex_init(&h->lock, NULL);
    if (reading)
        pthread_create(&h->tid, NULL, host_reader, h);
    hosts[num_hosts++] = h;
    sleep_ms(150 * slow);
    return h;
}

static void host_send(struct host *h, const uint8_t dst[MAC_LEN], const char *text, int vlan, int prio)
{
    uint8_t buf[HDR_LEN + MAX_PAYLOAD];
    size_t n = pack_frame(buf, h->mac, dst, text, vlan, prio);
    if (write_full(h->fd, buf, n) < 0)
        return;
}

static int host_has(struct host *h, const char *text)
{
    int found = 0;
    pthread_mutex_lock(&h->lock);
    for (int i = 0; i < h->count && !found; i++)
        if (strcmp(h->rec[i].text, text) == 0)
            found = 1;
    pthread_mutex_unlock(&h->lock);
    return found;
}

static int host_got(struct host *h, const char *text, int seconds)
{
    double end = now() + seconds * slow;
    while (now() < end) {
        if (host_has(h, text))
            return 1;
        sleep_ms(50);
    }
    return host_has(h, text);
}

static int host_closed(struct host *h, int seconds)
{
    double end = now() + seconds * slow;
    for (;;) {
        int c;
        pthread_mutex_lock(&h->lock);
        c = h->closed;
        pthread_mutex_unlock(&h->lock);
        if (c || now() >= end)
            return c;
        sleep_ms(50);
    }
}

static int host_count(struct host *h)
{
    int c;
    pthread_mutex_lock(&h->lock);
    c = h->count;
    pthread_mutex_unlock(&h->lock);
    return c;
}

static void hosts_cleanup(void)
{
    for (int i = 0; i < num_hosts; i++) {
        struct host *h = hosts[i];
        shutdown(h->fd, SHUT_RDWR);
        if (h->reading)
            pthread_join(h->tid, NULL);
        close(h->fd);
        pthread_mutex_destroy(&h->lock);
        free(h);
    }
    num_hosts = 0;
}

/* ------------------------------------------------------------------ tests */

static int test_basic(struct sw *s)
{
    uint8_t ma[MAC_LEN];
    if (sw_start(s, 4, NULL) < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    struct host *c = host_open(s, "02:00:00:00:00:0c", 1);
    CHECK(a && b && c, "could not connect hosts");
    mac("02:00:00:00:00:0a", ma);
    host_send(a, bcast, "hello all", 1, 1);
    CHECK(host_got(b, "hello all", 2) && host_got(c, "hello all", 2), "broadcast did not reach every other host");
    host_send(b, ma, "just for A", 1, 1);
    CHECK(host_got(a, "just for A", 2), "unicast to a known MAC did not arrive");
    sleep_ms(300);
    CHECK(!host_has(c, "just for A"), "unicast to a known MAC was flooded to other ports");
    return 0;
}

static int test_partial_frames(struct sw *s)
{
    uint8_t buf[HDR_LEN + MAX_PAYLOAD], src[MAC_LEN];
    size_t n;
    if (sw_start(s, 4, NULL) < 0)
        return -1;
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    int fd = connect_switch(s);
    CHECK(b && fd >= 0, "could not connect hosts");
    mac("02:00:00:00:00:99", src);
    n = pack_frame(buf, src, bcast, "split frame", 1, 1);
    for (size_t i = 0; i < n; i++) {
        if (write(fd, buf + i, 1) != 1)
            break;
        sleep_ms(10);
    }
    n = pack_frame(buf, src, bcast, "never finished", 1, 1);
    if (write(fd, buf, 9) != 9)
        perror("write");
    close(fd);
    CHECK(host_got(b, "split frame", 2), "a frame sent one byte at a time was not received");
    CHECK(sw_log_has(s, "host disconnected", 3), "switch did not notice the host disconnecting mid-frame");
    struct host *c = host_open(s, "02:00:00:00:00:0c", 1);
    CHECK(c != NULL, "could not connect host after the broken one");
    host_send(c, bcast, "still alive", 1, 1);
    CHECK(host_got(b, "still alive", 2), "switch stopped working after a host died mid-frame");
    return 0;
}

struct blast {
    int fd;
    uint8_t *buf;
    size_t len;
};

static void *blast_thread(void *arg)
{
    struct blast *b = arg;
    if (write_full(b->fd, b->buf, b->len) < 0)
        return NULL;
    return NULL;
}

static int test_frozen_host(struct sw *s)
{
    char text[256];
    struct blast bl;
    pthread_t tid;
    int frames = 20000 / slow;
    size_t one;
    double start, elapsed;

    if (sw_start(s, 4, NULL) < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    struct host *c = host_open(s, "02:00:00:00:00:0c", 0);
    CHECK(a && b && c, "could not connect hosts");
    host_send(c, bcast, "learn me", 1, 1);
    sleep_ms(300);

    memset(text, 'x', 200);
    text[200] = '\0';
    one = HDR_LEN + 200;
    bl.fd = a->fd;
    bl.len = one * (size_t)frames;
    bl.buf = malloc(bl.len);
    CHECK(bl.buf != NULL, "out of memory");
    for (int i = 0; i < frames; i++)
        pack_frame(bl.buf + one * (size_t)i, a->mac, c->mac, text, 1, 1);
    pthread_create(&tid, NULL, blast_thread, &bl);
    sleep_ms(300);

    start = now();
    host_send(b, a->mac, "still fast", 1, 1);
    int ok = host_got(a, "still fast", 2);
    elapsed = now() - start;
    pthread_join(tid, NULL);
    free(bl.buf);
    CHECK(ok, "a frozen host slowed down the other hosts");
    CHECK(elapsed < 2.0 * slow, "message took %.1f s", elapsed);
    CHECK(stats_value(3, 2) > 0, "frozen port 3 shows no dropped frames in swctl stats");
    return 0;
}

static int test_switch_full(struct sw *s)
{
    double start, waited;
    if (sw_start(s, 2, "port_wait 2\n") < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    start = now();
    struct host *c = host_open(s, "02:00:00:00:00:0c", 1);
    CHECK(a && b && c, "could not connect hosts");
    CHECK(host_got(c, "switch full", 6), "extra host did not get 'switch full'");
    waited = now() - start;
    CHECK(waited >= 1.5, "extra host was rejected after %.1f s instead of waiting", waited);
    CHECK(host_closed(c, 2), "extra host was not disconnected");
    return 0;
}

static int test_port_freed(struct sw *s)
{
    if (sw_start(s, 2, "port_wait 5\n") < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    struct host *c = host_open(s, "02:00:00:00:00:0c", 1);
    CHECK(a && b && c, "could not connect hosts");
    sleep_ms(500);
    shutdown(b->fd, SHUT_RDWR);
    CHECK(sw_log_has(s, "host connected on port 2", 4), "waiting host did not get the freed port");
    CHECK(!host_has(c, "switch full"), "waiting host was rejected although a port became free");
    return 0;
}

static int test_mac_learning(struct sw *s)
{
    char out[BIG];
    if (sw_start(s, 4, NULL) < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    CHECK(a && b, "could not connect hosts");
    host_send(a, bcast, "a", 1, 1);
    host_send(b, bcast, "b", 1, 1);
    sleep_ms(300 * slow);
    swctl(out, sizeof out, "show mac");
    CHECK(strstr(out, "02:00:00:00:00:0a  1") && strstr(out, "02:00:00:00:00:0b  2"), "show mac is wrong:\n%.3000s", out);
    struct host *a2 = host_open(s, "02:00:00:00:00:0a", 1);
    CHECK(a2 != NULL, "could not connect host");
    host_send(a2, bcast, "moved", 1, 1);
    CHECK(sw_log_has(s, "MAC moved: 02:00:00:00:00:0a from port 1 to port 3", 3), "no 'MAC moved' log line");
    return 0;
}

static int test_aging(struct sw *s)
{
    if (sw_start(s, 4, "mac_age 2\n") < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    CHECK(a != NULL, "could not connect host");
    host_send(a, bcast, "once", 1, 1);
    sleep_ms(300 * slow);
    CHECK(swctl_has("show mac", "1 entries"), "MAC was not learned");
    CHECK(sw_log_has(s, "removed (aged out)", 5), "entry did not age out");
    CHECK(swctl_has("show mac", "0 entries"), "table not empty after aging");
    return 0;
}

static int test_lru(struct sw *s)
{
    uint8_t buf[HDR_LEN + MAX_PAYLOAD], src[MAC_LEN];
    char m[32];
    if (sw_start(s, 4, "mac_max 4\nmac_per_port 100\n") < 0)
        return -1;
    int fd = connect_switch(s);
    CHECK(fd >= 0, "could not connect");
    for (int i = 0; i < 6; i++) {
        snprintf(m, sizeof m, "02:00:00:00:02:%02x", i);
        mac(m, src);
        size_t n = pack_frame(buf, src, bcast, "m", 1, 1);
        if (write_full(fd, buf, n) < 0)
            break;
        sleep_ms(50);
    }
    int evicted = sw_log_has(s, "mac table full, evicted 02:00:00:00:02:00", 3);
    int size_ok = swctl_has("show mac", "4 entries");
    close(fd);
    CHECK(evicted, "oldest entry was not evicted");
    CHECK(size_ok, "table holds more than mac_max entries");
    return 0;
}

static int test_port_security(struct sw *s)
{
    uint8_t buf[HDR_LEN + MAX_PAYLOAD], src[MAC_LEN];
    char m[32];
    if (sw_start(s, 4, "mac_per_port 4\n") < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    int fd = connect_switch(s);
    CHECK(a && fd >= 0, "could not connect");
    for (int i = 0; i < 10; i++) {
        snprintf(m, sizeof m, "02:00:00:00:01:%02x", i);
        mac(m, src);
        size_t n = pack_frame(buf, src, bcast, "m", 1, 1);
        if (write_full(fd, buf, n) < 0)
            break;
        sleep_ms(50);
    }
    close(fd);
    CHECK(sw_log_has(s, "too many MACs", 3), "port was not shut down after too many MACs");
    CHECK(swctl_has("show ports", "2     disabled"), "port 2 is not shown as disabled");
    swctl_has("up 2", "");
    CHECK(!swctl_has("show ports", "2     disabled"), "'swctl up' did not enable the port");
    return 0;
}

static int test_vlans(struct sw *s)
{
    if (sw_start(s, 4, "vlan 1 10\nvlan 2 10\nvlan 3 20\ntrunk 4\n") < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    struct host *c = host_open(s, "02:00:00:00:00:0c", 1);
    struct host *t = host_open(s, "02:00:00:00:00:0f", 1);
    CHECK(a && b && c && t, "could not connect hosts");
    host_send(a, bcast, "vlan10 broadcast", 1, 1);
    CHECK(host_got(b, "vlan10 broadcast", 2) && host_got(t, "vlan10 broadcast", 2),
          "broadcast did not reach its own VLAN and the trunk");
    host_send(t, bcast, "tagged 20", 20, 1);
    CHECK(host_got(c, "tagged 20", 2), "tagged frame from the trunk did not reach VLAN 20");
    sleep_ms(300);
    CHECK(!host_has(c, "vlan10 broadcast"), "broadcast leaked into another VLAN");
    CHECK(!host_has(a, "tagged 20") && !host_has(b, "tagged 20"), "trunk frame for VLAN 20 leaked into VLAN 10");
    pthread_mutex_lock(&t->lock);
    int vlan = t->count > 0 ? t->rec[0].vlan : -1;
    pthread_mutex_unlock(&t->lock);
    CHECK(vlan == 10, "trunk did not keep the vlan field (got %d)", vlan);
    host_send(t, bcast, "bad tag", 0, 1);
    CHECK(sw_log_has(s, "bad vlan 0 on trunk", 3), "frame with vlan 0 on the trunk was not dropped");
    return 0;
}

static int test_qos(struct sw *s)
{
    char text[16], order[512] = "";
    double start, elapsed, end;
    int first_high = -1, last_high = -1, last_low = -1, lows_between = 0, n = 0;

    if (sw_start(s, 4, "rate_limit 10\nwrr 5 3 1\n") < 0)
        return -1;
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    CHECK(a && b, "could not connect hosts");
    host_send(b, bcast, "learn b", 1, 1);
    sleep_ms(300);
    start = now();
    for (int i = 0; i < 20; i++) {
        snprintf(text, sizeof text, "L%d", i);
        host_send(a, b->mac, text, 1, 2);
    }
    for (int i = 0; i < 20; i++) {
        snprintf(text, sizeof text, "H%d", i);
        host_send(a, b->mac, text, 1, 0);
    }
    end = now() + 8 * slow;
    while (host_count(b) < 40 && now() < end)
        sleep_ms(50);
    elapsed = now() - start;
    CHECK(host_count(b) >= 40, "only %d of 40 frames arrived", host_count(b));

    pthread_mutex_lock(&b->lock);
    for (int i = 0; i < b->count; i++) {
        char k = b->rec[i].text[0];
        if (k != 'L' && k != 'H')
            continue;
        if (k == 'H') {
            if (first_high < 0)
                first_high = n;
            last_high = n;
        } else {
            last_low = n;
        }
        strncat(order, b->rec[i].text, sizeof order - strlen(order) - 2);
        strcat(order, " ");
        n++;
    }
    for (int i = 0, k = 0; i < b->count; i++) {
        char c = b->rec[i].text[0];
        if (c != 'L' && c != 'H')
            continue;
        if (c == 'L' && k > first_high && k < last_high)
            lows_between++;
        k++;
    }
    pthread_mutex_unlock(&b->lock);

    CHECK(elapsed >= 1.8, "40 frames at 10/s took only %.1f s, rate limit not working", elapsed);
    CHECK(last_high < last_low, "high priority frames were not sent first: %s", order);
    CHECK(lows_between >= 1, "low priority frames were starved: %s", order);
    return 0;
}

static int test_mirroring(struct sw *s)
{
    if (sw_start(s, 4, NULL) < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    struct host *c = host_open(s, "02:00:00:00:00:0c", 1);
    CHECK(a && b && c, "could not connect hosts");
    host_send(a, bcast, "a", 1, 1);
    host_send(b, bcast, "b", 1, 1);
    sleep_ms(300);
    CHECK(swctl_has("mirror 1 3", "mirrored to port 3"), "mirror command failed");
    host_send(a, b->mac, "A to B", 1, 1);
    host_send(b, a->mac, "B to A", 1, 1);
    CHECK(host_got(c, "A to B", 2) && host_got(c, "B to A", 2), "sniffer did not get traffic in and out of port 1");
    swctl_has("mirror 1 0", "");
    host_send(a, b->mac, "not mirrored", 1, 1);
    CHECK(host_got(b, "not mirrored", 2), "unicast stopped working");
    sleep_ms(300);
    CHECK(!host_has(c, "not mirrored"), "mirroring did not stop");
    CHECK(stats_value(1, 3) >= 2, "mirrored counter of port 1 not updated");
    return 0;
}

struct flood {
    struct host *h;
    int stop;
    pthread_mutex_t lock;
};

static void *flood_thread(void *arg)
{
    struct flood *f = arg;
    char text[501];
    uint8_t buf[HDR_LEN + MAX_PAYLOAD];
    size_t n;

    memset(text, 'y', 500);
    text[500] = '\0';
    n = pack_frame(buf, f->h->mac, bcast, text, 1, 1);
    for (;;) {
        int stop;
        pthread_mutex_lock(&f->lock);
        stop = f->stop;
        pthread_mutex_unlock(&f->lock);
        if (stop || write_full(f->h->fd, buf, n) < 0)
            break;
    }
    return NULL;
}

static int test_live_reconfig(struct sw *s)
{
    struct flood fl;
    pthread_t tid;
    int shut_ok, closed_ok, disabled_ok;

    if (sw_start(s, 4, NULL) < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    CHECK(a && b, "could not connect hosts");
    swctl_has("vlan 2 5", "");
    host_send(a, bcast, "after vlan change", 1, 1);
    sleep_ms(400);
    CHECK(!host_has(b, "after vlan change"), "'swctl vlan' did not move the port");
    swctl_has("vlan 2 1", "");

    fl.h = a;
    fl.stop = 0;
    pthread_mutex_init(&fl.lock, NULL);
    pthread_create(&tid, NULL, flood_thread, &fl);
    sleep_ms(500);
    shut_ok = swctl_has("shutdown 2", "port 2 shut down");
    closed_ok = host_closed(b, 3);
    disabled_ok = swctl_has("show ports", "2     disabled");
    struct host *d = host_open(s, "02:00:00:00:00:0d", 1);
    int skipped = sw_log_has(s, "host connected on port 3", 3);
    swctl_has("up 2", "");
    struct host *e = host_open(s, "02:00:00:00:00:0e", 1);
    int reused = sw_log_has(s, "host connected on port 2", 3);
    pthread_mutex_lock(&fl.lock);
    fl.stop = 1;
    pthread_mutex_unlock(&fl.lock);
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&fl.lock);

    CHECK(shut_ok, "shutdown under load failed");
    CHECK(closed_ok, "host on the shut down port was not disconnected");
    CHECK(disabled_ok, "port 2 not shown as disabled");
    CHECK(d && skipped, "new host did not skip the disabled port");
    CHECK(e && reused, "port 2 did not take hosts after 'swctl up'");

    host_send(d, bcast, "d", 1, 1);
    double end = now() + 2 * slow;
    while (!swctl_has("show mac", "02:00:00:00:00:0d") && now() < end)
        sleep_ms(50);
    CHECK(swctl_has("show mac", "02:00:00:00:00:0d"), "MAC of the new host not learned");
    CHECK(swctl_has("clear mac", "cleared"), "clear mac failed");
    CHECK(!swctl_has("show mac", "02:00:00:00:00:0d"), "MAC table not cleared by clear mac");
    CHECK(swctl_has("bogus", "unknown command"), "unknown command not reported");
    return 0;
}

static int test_signals(struct sw *s)
{
    char path[256];
    FILE *fp;
    if (sw_start(s, 4, "vlan 3 20\n") < 0)
        return -1;
    struct host *a = host_open(s, "02:00:00:00:00:0a", 1);
    struct host *b = host_open(s, "02:00:00:00:00:0b", 1);
    CHECK(a && b, "could not connect hosts");
    host_send(a, bcast, "a", 1, 1);
    sleep_ms(300 * slow);

    kill(s->pid, SIGUSR1);
    CHECK(sw_log_has(s, "SIGUSR1: mac table written", 3), "SIGUSR1 did not dump the MAC table");
    snprintf(path, sizeof path, "%s/mac_dump.txt", s->dir);
    CHECK(file_has(path, "02:00:00:00:00:0a"), "mac_dump.txt does not contain the learned MAC");

    fp = fopen(s->conf, "w");
    CHECK(fp != NULL, "cannot rewrite config");
    fputs("vlan 3 30\n", fp);
    fclose(fp);
    kill(s->pid, SIGHUP);
    CHECK(sw_log_has(s, "SIGHUP: config reloaded", 3), "SIGHUP did not reload the config");
    CHECK(swctl_has("show ports", "3     free      30"), "reloaded VLAN not applied");

    int code = sw_stop(s);
    CHECK(code == 0, "switch exit code after SIGINT: %d", code);
    CHECK(file_has(s->out, "switch stopped cleanly"), "no clean shutdown message");
    CHECK(host_closed(a, 3) && host_closed(b, 3), "hosts were not disconnected on shutdown");
    CHECK(swctl_has("stats", "cannot open shared memory"), "shared memory was not removed");
    CHECK(access("/tmp/vswitch.sock", F_OK) != 0, "admin socket was not removed");
    snprintf(path, sizeof path, "%s/switch.log", s->dir);
    CHECK(file_has(path, "] host connected on port 1"), "switch.log has no timestamped lines");
    return 0;
}

struct test {
    const char *name;
    int (*fn)(struct sw *);
};

static const struct test tests[] = {
    { "basic connect, broadcast and unicast (item 1)", test_basic },
    { "partial frames and a host dying mid-frame (item 1)", test_partial_frames },
    { "frozen host does not slow the others (items 2, 3)", test_frozen_host },
    { "switch full after waiting (item 5)", test_switch_full },
    { "waiting host gets a port that frees up (item 5)", test_port_freed },
    { "MAC learning and host moves (item 4)", test_mac_learning },
    { "MAC aging (item 4)", test_aging },
    { "MAC table size limit with LRU eviction (item 4)", test_lru },
    { "port security (item 4)", test_port_security },
    { "VLANs and trunk port (item 8)", test_vlans },
    { "QoS priorities and rate limiting (items 6, 7)", test_qos },
    { "port mirroring (item 9)", test_mirroring },
    { "live reconfiguration with swctl (items 10, 11)", test_live_reconfig },
    { "signals, clean shutdown and logging (items 12, 13)", test_signals },
};

static int check_tools(struct sw *s)
{
    if (mode == MODE_TSAN)
        CHECK(!file_has(s->out, "WARNING: ThreadSanitizer"), "ThreadSanitizer warning, see %s", s->out);
    if (mode == MODE_VALGRIND) {
        CHECK(file_has(s->vglog, "ERROR SUMMARY: 0 errors"), "valgrind reported errors, see %s", s->vglog);
        CHECK(!file_has(s->vglog, "definitely lost: ") || file_has(s->vglog, "definitely lost: 0 bytes"),
              "valgrind found leaks, see %s", s->vglog);
    }
    return 0;
}

static void remove_dir(const char *dir)
{
    char cmd[256];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "could not remove %s\n", dir);
}

int main(int argc, char *argv[])
{
    int passed = 0;
    int total = (int)(sizeof tests / sizeof tests[0]);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tsan") == 0)
            mode = MODE_TSAN;
        else if (strcmp(argv[i], "--valgrind") == 0)
            mode = MODE_VALGRIND;
    }
    slow = mode == MODE_VALGRIND ? 4 : 1;
    next_port = 20000 + getpid() % 20000;
    if (getcwd(here, sizeof here) == NULL) {
        perror("getcwd");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    if (system(mode == MODE_TSAN ? "make -s all tsan" : "make -s all") != 0) {
        printf("[FAIL] build\n");
        return 1;
    }
    if (mode == MODE_VALGRIND && system("which valgrind > /dev/null") != 0) {
        printf("valgrind is not installed: sudo apt install valgrind\n");
        return 1;
    }
    printf("build ok, mode: %s\n\n",
           mode == MODE_TSAN ? "tsan" : mode == MODE_VALGRIND ? "valgrind" : "normal");

    for (int i = 0; i < total; i++) {
        struct sw s;
        int ok;

        memset(&s, 0, sizeof s);
        cur_sw = NULL;
        fail_msg[0] = '\0';
        ok = tests[i].fn(&s) == 0;
        if (s.running) {
            int code = sw_stop(&s);
            if (ok && code != 0) {
                snprintf(fail_msg, sizeof fail_msg, "switch exit code after SIGINT: %d", code);
                ok = 0;
            }
        }
        hosts_cleanup();
        if (ok && cur_sw != NULL && check_tools(&s) < 0)
            ok = 0;

        if (ok) {
            printf("[PASS] %2d. %s\n", i + 1, tests[i].name);
            passed++;
            if (s.dir[0] != '\0')
                remove_dir(s.dir);
        } else {
            printf("[FAIL] %2d. %s\n       %s\n", i + 1, tests[i].name, fail_msg);
            if (s.dir[0] != '\0')
                printf("       switch output kept in %s\n", s.out);
        }
        fflush(stdout);
    }

    printf("\n%d of %d tests passed\n", passed, total);
    return passed == total ? 0 : 1;
}
