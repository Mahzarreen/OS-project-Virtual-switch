/* queue.c - refcounted frames, 3 priority rings picked by weighted round robin, token bucket rate limit */
#define _GNU_SOURCE
#include "queue.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

struct pkt *pkt_new(const struct frame *f)
{
    struct pkt *p = malloc(sizeof *p);
    if (p == NULL)
        return NULL;
    p->f = *f;
    p->born_ms = now_ms();
    p->refcount = 1;
    if (pthread_mutex_init(&p->lock, NULL) != 0) {
        free(p);
        return NULL;
    }
    return p;
}

void pkt_ref(struct pkt *p)
{
    pthread_mutex_lock(&p->lock);
    p->refcount++;
    pthread_mutex_unlock(&p->lock);
}

void pkt_unref(struct pkt *p)
{
    int last;

    pthread_mutex_lock(&p->lock);
    p->refcount--;
    last = (p->refcount == 0);
    pthread_mutex_unlock(&p->lock);

    if (last) {
        pthread_mutex_destroy(&p->lock);
        free(p);
    }
}

int queue_init(struct queue *q, int cap, const int weights[NUM_PRIO], int rate)
{
    memset(q, 0, sizeof *q);
    q->cap = cap;
    q->rate = rate;
    q->tokens = rate;
    for (int c = 0; c < NUM_PRIO; c++) {
        q->ring[c].items = calloc((size_t)cap, sizeof(struct pkt *));
        if (q->ring[c].items == NULL)
            return -1;
        q->weight[c] = weights[c];
        q->credit[c] = weights[c];
    }
    if (pthread_mutex_init(&q->lock, NULL) != 0 ||
        pthread_cond_init(&q->not_empty, NULL) != 0 ||
        pthread_cond_init(&q->has_tokens, NULL) != 0)
        return -1;
    return 0;
}

void queue_destroy(struct queue *q)
{
    queue_drain(q);
    pthread_cond_destroy(&q->has_tokens);
    pthread_cond_destroy(&q->not_empty);
    pthread_mutex_destroy(&q->lock);
    for (int c = 0; c < NUM_PRIO; c++)
        free(q->ring[c].items);
}

static int total_count(struct queue *q)
{
    return q->ring[0].count + q->ring[1].count + q->ring[2].count;
}

static struct pkt *ring_pop(struct queue *q, int c)
{
    struct ring *r = &q->ring[c];
    struct pkt *p = r->items[r->head];
    r->head = (r->head + 1) % q->cap;
    r->count--;
    return p;
}

int queue_push(struct queue *q, struct pkt *p)
{
    int c = p->f.priority;
    struct ring *r = &q->ring[c];

    pthread_mutex_lock(&q->lock);
    if (q->closing || r->count == q->cap) {
        q->dropped++;
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    r->items[r->tail] = p;
    r->tail = (r->tail + 1) % q->cap;
    r->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

static int pick_class(struct queue *q)
{
    long long now = now_ms();
    int aged = -1;

    for (int c = 1; c < NUM_PRIO; c++) {
        struct ring *r = &q->ring[c];
        if (r->count == 0 || now - r->items[r->head]->born_ms < QOS_AGE_MS)
            continue;
        if (aged < 0 || r->items[r->head]->born_ms < q->ring[aged].items[q->ring[aged].head]->born_ms)
            aged = c;
    }
    if (aged >= 0 && !q->aged_used) {
        q->aged_used = 1;
        return aged;
    }

    for (int i = 0; i < 2 * NUM_PRIO; i++) {
        int c = q->cur;
        if (q->ring[c].count > 0 && q->credit[c] > 0) {
            q->credit[c]--;
            return c;
        }
        q->cur = (q->cur + 1) % NUM_PRIO;
        if (q->cur == 0) {
            memcpy(q->credit, q->weight, sizeof q->credit);
            q->aged_used = 0;
        }
    }

    for (int c = 0; c < NUM_PRIO; c++)
        if (q->ring[c].count > 0)
            return c;
    return 0;
}

struct pkt *queue_pop(struct queue *q)
{
    struct pkt *p;

    pthread_mutex_lock(&q->lock);
    for (;;) {
        if (q->closing) {
            pthread_mutex_unlock(&q->lock);
            return NULL;
        }
        if (total_count(q) == 0) {
            pthread_cond_wait(&q->not_empty, &q->lock);
            continue;
        }
        if (q->rate > 0 && q->tokens == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            if (pthread_cond_timedwait(&q->has_tokens, &q->lock, &ts) == EINVAL) {
                pthread_mutex_unlock(&q->lock);
                return NULL;
            }
            continue;
        }
        break;
    }
    p = ring_pop(q, pick_class(q));
    if (q->rate > 0)
        q->tokens--;
    pthread_mutex_unlock(&q->lock);
    return p;
}

void queue_refill(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    q->tokens = q->rate;
    pthread_cond_broadcast(&q->has_tokens);
    pthread_mutex_unlock(&q->lock);
}

void queue_close(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    q->closing = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->has_tokens);
    pthread_mutex_unlock(&q->lock);
}

void queue_drain(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    for (int c = 0; c < NUM_PRIO; c++)
        while (q->ring[c].count > 0)
            pkt_unref(ring_pop(q, c));
    pthread_mutex_unlock(&q->lock);
}

void queue_reset(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    q->closing = 0;
    q->dropped = 0;
    q->tokens = q->rate;
    q->cur = 0;
    q->aged_used = 0;
    for (int c = 0; c < NUM_PRIO; c++) {
        q->ring[c].head = 0;
        q->ring[c].tail = 0;
        q->credit[c] = q->weight[c];
    }
    pthread_mutex_unlock(&q->lock);
}

void queue_set_limits(struct queue *q, int rate, const int weights[NUM_PRIO])
{
    pthread_mutex_lock(&q->lock);
    q->rate = rate;
    if (q->tokens > rate)
        q->tokens = rate;
    for (int c = 0; c < NUM_PRIO; c++) {
        q->weight[c] = weights[c];
        if (q->credit[c] > weights[c])
            q->credit[c] = weights[c];
    }
    pthread_cond_broadcast(&q->has_tokens);
    pthread_mutex_unlock(&q->lock);
}

unsigned long queue_dropped(struct queue *q)
{
    unsigned long d;
    pthread_mutex_lock(&q->lock);
    d = q->dropped;
    pthread_mutex_unlock(&q->lock);
    return d;
}
