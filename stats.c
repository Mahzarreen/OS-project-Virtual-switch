/* stats.c - creates/opens the shared memory stats block (switch side and swctl side) */
#define _GNU_SOURCE
#include "stats.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static struct switch_stats *stats;

int stats_create(int num_ports)
{
    pthread_mutexattr_t attr;
    int fd = shm_open(STATS_SHM_NAME, O_CREAT | O_RDWR, 0600);

    if (fd < 0) {
        perror("shm_open");
        return -1;
    }
    if (ftruncate(fd, sizeof(struct switch_stats)) < 0) {
        perror("ftruncate");
        close(fd);
        return -1;
    }
    stats = mmap(NULL, sizeof(struct switch_stats), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (stats == MAP_FAILED) {
        perror("mmap");
        stats = NULL;
        return -1;
    }
    memset(stats, 0, sizeof *stats);
    stats->num_ports = num_ports;

    if (pthread_mutexattr_init(&attr) != 0 ||
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED) != 0 ||
        pthread_mutex_init(&stats->lock, &attr) != 0) {
        fprintf(stderr, "cannot create process-shared mutex\n");
        return -1;
    }
    pthread_mutexattr_destroy(&attr);
    return 0;
}

void stats_destroy(void)
{
    if (stats == NULL)
        return;
    pthread_mutex_destroy(&stats->lock);
    munmap(stats, sizeof *stats);
    stats = NULL;
    if (shm_unlink(STATS_SHM_NAME) < 0)
        perror("shm_unlink");
}

void stats_inc(int port, int which)
{
    if (stats == NULL || port < 0 || port >= stats->num_ports)
        return;
    pthread_mutex_lock(&stats->lock);
    switch (which) {
    case STAT_IN:
        stats->port[port].in++;
        break;
    case STAT_OUT:
        stats->port[port].out++;
        break;
    case STAT_DROPPED:
        stats->port[port].dropped++;
        break;
    case STAT_MIRRORED:
        stats->port[port].mirrored++;
        break;
    }
    pthread_mutex_unlock(&stats->lock);
}

struct switch_stats *stats_open(void)
{
    struct switch_stats *s;
    int fd = shm_open(STATS_SHM_NAME, O_RDWR, 0);

    if (fd < 0)
        return NULL;
    s = mmap(NULL, sizeof *s, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (s == MAP_FAILED)
        return NULL;
    return s;
}

void stats_close(struct switch_stats *s)
{
    munmap(s, sizeof *s);
}
