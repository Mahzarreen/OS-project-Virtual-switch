/* queue.h - shared refcounted frames and the per-port output queue with 3 priorities and a token bucket */
#ifndef QUEUE_H
#define QUEUE_H

#include <pthread.h>
#include "frame.h"

#define NUM_PRIO 3
#define QOS_AGE_MS 1000

struct pkt {
    struct frame f;
    long long born_ms;
    int refcount;
    pthread_mutex_t lock;
};

struct ring {
    struct pkt **items;
    int head;
    int tail;
    int count;
};

struct queue {
    struct ring ring[NUM_PRIO];
    int cap;
    int weight[NUM_PRIO];
    int credit[NUM_PRIO];
    int cur;
    int aged_used;
    int rate;
    int tokens;
    int closing;
    unsigned long dropped;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t has_tokens;
};

long long now_ms(void);

struct pkt *pkt_new(const struct frame *f);
void pkt_ref(struct pkt *p);
void pkt_unref(struct pkt *p);

int queue_init(struct queue *q, int cap, const int weights[NUM_PRIO], int rate);
void queue_destroy(struct queue *q);
int queue_push(struct queue *q, struct pkt *p);
struct pkt *queue_pop(struct queue *q);
void queue_refill(struct queue *q);
void queue_close(struct queue *q);
void queue_drain(struct queue *q);
void queue_reset(struct queue *q);
unsigned long queue_dropped(struct queue *q);

#endif
