/* mactable.c - striped-lock MAC table: learning, lookup, host moves, aging thread and LRU eviction */
#define _GNU_SOURCE
#include "mactable.h"
#include "logger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static time_t now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

static unsigned int hash_mac(const uint8_t mac[MAC_LEN])
{
    unsigned int h = 5381;
    for (int i = 0; i < MAC_LEN; i++)
        h = h * 33 + mac[i];
    return h % MAC_BUCKETS;
}

static struct mac_entry *find_in_bucket(struct mac_table *t, unsigned int b, const uint8_t mac[MAC_LEN])
{
    for (struct mac_entry *e = t->buckets[b]; e != NULL; e = e->next)
        if (memcmp(e->mac, mac, MAC_LEN) == 0)
            return e;
    return NULL;
}

static void forget_entry(struct mac_table *t, struct mac_entry *e)
{
    pthread_mutex_lock(&t->count_lock);
    t->count--;
    t->port_count[e->port]--;
    pthread_mutex_unlock(&t->count_lock);
    free(e);
}

int mac_table_init(struct mac_table *t, int num_ports, int max_entries, int max_per_port, int age_seconds)
{
    memset(t, 0, sizeof *t);
    t->port_count = calloc((size_t)num_ports, sizeof *t->port_count);
    if (t->port_count == NULL)
        return -1;
    t->num_ports = num_ports;
    t->max_entries = max_entries;
    t->max_per_port = max_per_port;
    t->age_seconds = age_seconds;

    for (int i = 0; i < MAC_BUCKETS; i++)
        if (pthread_mutex_init(&t->bucket_lock[i], NULL) != 0)
            return -1;
    if (pthread_mutex_init(&t->count_lock, NULL) != 0 ||
        pthread_mutex_init(&t->stop_lock, NULL) != 0 ||
        pthread_cond_init(&t->stop_cond, NULL) != 0)
        return -1;
    return 0;
}

static void evict_oldest(struct mac_table *t)
{
    uint8_t victim[MAC_LEN];
    long long oldest = 0;
    int found = 0;

    for (int b = 0; b < MAC_BUCKETS; b++) {
        pthread_mutex_lock(&t->bucket_lock[b]);
        for (struct mac_entry *e = t->buckets[b]; e != NULL; e = e->next) {
            if (!found || e->last_used < oldest) {
                oldest = e->last_used;
                memcpy(victim, e->mac, MAC_LEN);
                found = 1;
            }
        }
        pthread_mutex_unlock(&t->bucket_lock[b]);
    }
    if (!found)
        return;

    unsigned int b = hash_mac(victim);
    pthread_mutex_lock(&t->bucket_lock[b]);
    struct mac_entry **pp = &t->buckets[b];
    while (*pp != NULL) {
        if (memcmp((*pp)->mac, victim, MAC_LEN) == 0) {
            struct mac_entry *e = *pp;
            char s[18];
            *pp = e->next;
            mac_to_str(e->mac, s);
            log_msg("mac table full, evicted %s", s);
            forget_entry(t, e);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&t->bucket_lock[b]);
}

static int reserve_slot(struct mac_table *t, int port)
{
    for (int tries = 0; tries < 3; tries++) {
        pthread_mutex_lock(&t->count_lock);
        if (t->port_count[port] >= t->max_per_port) {
            pthread_mutex_unlock(&t->count_lock);
            return MAC_VIOLATION;
        }
        if (t->count < t->max_entries) {
            t->count++;
            t->port_count[port]++;
            pthread_mutex_unlock(&t->count_lock);
            return MAC_OK;
        }
        pthread_mutex_unlock(&t->count_lock);
        evict_oldest(t);
    }
    pthread_mutex_lock(&t->count_lock);
    t->count++;
    t->port_count[port]++;
    pthread_mutex_unlock(&t->count_lock);
    return MAC_OK;
}

static void undo_reserve(struct mac_table *t, int port)
{
    pthread_mutex_lock(&t->count_lock);
    t->count--;
    t->port_count[port]--;
    pthread_mutex_unlock(&t->count_lock);
}

static int update_entry(struct mac_table *t, struct mac_entry *e, int port, int *old_port)
{
    e->last_seen = now_sec();
    e->last_used = now_ms();
    if (e->port == port)
        return MAC_OK;

    pthread_mutex_lock(&t->count_lock);
    if (t->port_count[port] >= t->max_per_port) {
        pthread_mutex_unlock(&t->count_lock);
        return MAC_VIOLATION;
    }
    t->port_count[e->port]--;
    t->port_count[port]++;
    pthread_mutex_unlock(&t->count_lock);

    *old_port = e->port;
    e->port = port;
    return MAC_MOVED;
}

int mac_learn(struct mac_table *t, const uint8_t mac[MAC_LEN], int port, int *old_port)
{
    unsigned int b = hash_mac(mac);
    struct mac_entry *e;
    int r;

    pthread_mutex_lock(&t->bucket_lock[b]);
    e = find_in_bucket(t, b, mac);
    if (e != NULL) {
        r = update_entry(t, e, port, old_port);
        pthread_mutex_unlock(&t->bucket_lock[b]);
        return r;
    }
    pthread_mutex_unlock(&t->bucket_lock[b]);

    if (reserve_slot(t, port) == MAC_VIOLATION)
        return MAC_VIOLATION;

    pthread_mutex_lock(&t->bucket_lock[b]);
    e = find_in_bucket(t, b, mac);
    if (e != NULL) {
        undo_reserve(t, port);
        r = update_entry(t, e, port, old_port);
        pthread_mutex_unlock(&t->bucket_lock[b]);
        return r;
    }

    e = malloc(sizeof *e);
    if (e == NULL) {
        undo_reserve(t, port);
        pthread_mutex_unlock(&t->bucket_lock[b]);
        return MAC_OK;
    }
    memcpy(e->mac, mac, MAC_LEN);
    e->port = port;
    e->last_seen = now_sec();
    e->last_used = now_ms();
    e->next = t->buckets[b];
    t->buckets[b] = e;
    pthread_mutex_unlock(&t->bucket_lock[b]);
    return MAC_OK;
}

int mac_lookup(struct mac_table *t, const uint8_t mac[MAC_LEN])
{
    unsigned int b = hash_mac(mac);
    int port = -1;

    pthread_mutex_lock(&t->bucket_lock[b]);
    struct mac_entry *e = find_in_bucket(t, b, mac);
    if (e != NULL) {
        e->last_used = now_ms();
        port = e->port;
    }
    pthread_mutex_unlock(&t->bucket_lock[b]);
    return port;
}

enum { RM_AGED, RM_PORT, RM_ALL };

static void remove_entries(struct mac_table *t, int mode, int port, time_t older_than)
{
    static const char *reason[] = { "aged out", "port down", "table cleared" };

    for (int b = 0; b < MAC_BUCKETS; b++) {
        pthread_mutex_lock(&t->bucket_lock[b]);
        struct mac_entry **pp = &t->buckets[b];
        while (*pp != NULL) {
            struct mac_entry *e = *pp;
            int remove = (mode == RM_ALL) ||
                         (mode == RM_PORT && e->port == port) ||
                         (mode == RM_AGED && e->last_seen < older_than);
            if (remove) {
                char s[18];
                mac_to_str(e->mac, s);
                log_msg("mac %s removed (%s)", s, reason[mode]);
                *pp = e->next;
                forget_entry(t, e);
            } else {
                pp = &e->next;
            }
        }
        pthread_mutex_unlock(&t->bucket_lock[b]);
    }
}

void mac_remove_port(struct mac_table *t, int port)
{
    remove_entries(t, RM_PORT, port, 0);
}

void mac_clear(struct mac_table *t)
{
    remove_entries(t, RM_ALL, -1, 0);
}

void mac_dump(struct mac_table *t, FILE *out)
{
    time_t now = now_sec();
    int total = 0;

    fprintf(out, "%-18s %-5s %s\n", "MAC", "PORT", "AGE(s)");
    for (int b = 0; b < MAC_BUCKETS; b++) {
        pthread_mutex_lock(&t->bucket_lock[b]);
        for (struct mac_entry *e = t->buckets[b]; e != NULL; e = e->next) {
            char s[18];
            mac_to_str(e->mac, s);
            fprintf(out, "%-18s %-5d %ld\n", s, e->port + 1, (long)(now - e->last_seen));
            total++;
        }
        pthread_mutex_unlock(&t->bucket_lock[b]);
    }
    fprintf(out, "%d entries\n", total);
}

static void *aging_thread(void *arg)
{
    struct mac_table *t = arg;

    pthread_mutex_lock(&t->stop_lock);
    while (!t->stopping) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        int r = pthread_cond_timedwait(&t->stop_cond, &t->stop_lock, &ts);
        if (r != 0 && r != ETIMEDOUT)
            break;
        if (t->stopping)
            break;
        int age = t->age_seconds;
        pthread_mutex_unlock(&t->stop_lock);
        remove_entries(t, RM_AGED, -1, now_sec() - age);
        pthread_mutex_lock(&t->stop_lock);
    }
    pthread_mutex_unlock(&t->stop_lock);
    return NULL;
}

void mac_table_set_limits(struct mac_table *t, int max_entries, int max_per_port, int age_seconds)
{
    pthread_mutex_lock(&t->count_lock);
    t->max_entries = max_entries;
    t->max_per_port = max_per_port;
    pthread_mutex_unlock(&t->count_lock);

    pthread_mutex_lock(&t->stop_lock);
    t->age_seconds = age_seconds;
    pthread_mutex_unlock(&t->stop_lock);
}

int mac_table_start_aging(struct mac_table *t)
{
    if (pthread_create(&t->ager, NULL, aging_thread, t) != 0)
        return -1;
    return 0;
}

void mac_table_stop_aging(struct mac_table *t)
{
    pthread_mutex_lock(&t->stop_lock);
    t->stopping = 1;
    pthread_cond_signal(&t->stop_cond);
    pthread_mutex_unlock(&t->stop_lock);
    pthread_join(t->ager, NULL);
}

void mac_table_destroy(struct mac_table *t)
{
    for (int b = 0; b < MAC_BUCKETS; b++) {
        struct mac_entry *e = t->buckets[b];
        while (e != NULL) {
            struct mac_entry *next = e->next;
            free(e);
            e = next;
        }
        t->buckets[b] = NULL;
        pthread_mutex_destroy(&t->bucket_lock[b]);
    }
    pthread_mutex_destroy(&t->count_lock);
    pthread_mutex_destroy(&t->stop_lock);
    pthread_cond_destroy(&t->stop_cond);
    free(t->port_count);
}
