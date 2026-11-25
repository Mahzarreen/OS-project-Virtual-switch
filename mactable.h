/* mactable.h - MAC address table with one lock per bucket, aging, LRU limit and port security */
#ifndef MACTABLE_H
#define MACTABLE_H

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "frame.h"

#define MAC_BUCKETS 64

enum { MAC_OK = 0, MAC_MOVED = 1, MAC_VIOLATION = -1 };

struct mac_entry {
    uint8_t mac[MAC_LEN];
    int port;
    time_t last_seen;
    long long last_used;
    struct mac_entry *next;
};

struct mac_table {
    struct mac_entry *buckets[MAC_BUCKETS];
    pthread_mutex_t bucket_lock[MAC_BUCKETS];

    pthread_mutex_t count_lock;
    int count;
    int max_entries;
    int *port_count;
    int num_ports;
    int max_per_port;
    int age_seconds;

    pthread_t ager;
    int stopping;
    pthread_mutex_t stop_lock;
    pthread_cond_t stop_cond;
};

int mac_table_init(struct mac_table *t, int num_ports, int max_entries, int max_per_port, int age_seconds);
int mac_table_start_aging(struct mac_table *t);
void mac_table_stop_aging(struct mac_table *t);
void mac_table_destroy(struct mac_table *t);

int mac_learn(struct mac_table *t, const uint8_t mac[MAC_LEN], int port, int *old_port);
int mac_lookup(struct mac_table *t, const uint8_t mac[MAC_LEN]);
void mac_remove_port(struct mac_table *t, int port);
void mac_clear(struct mac_table *t);
void mac_dump(struct mac_table *t, FILE *out);

#endif
