/* stats.h - per-port counters kept in POSIX shared memory, protected by a process-shared mutex */
#ifndef STATS_H
#define STATS_H

#include <pthread.h>
#include "config.h"

#define STATS_SHM_NAME "/vswitch_stats"

enum { STAT_IN, STAT_OUT, STAT_DROPPED, STAT_MIRRORED };

struct port_stats 
{
    unsigned long in;
    unsigned long out;
    unsigned long dropped;
    unsigned long mirrored;
};

struct switch_stats 
{
    pthread_mutex_t lock;
    int num_ports;
    struct port_stats port[MAX_PORTS];
};

int stats_create(int num_ports);
void stats_destroy();
void stats_inc(int port, int which);

struct switch_stats *stats_open();
void stats_close(struct switch_stats *s);

#endif
