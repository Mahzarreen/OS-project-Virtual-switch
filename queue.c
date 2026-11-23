/* queue.c - reference counted frames and a bounded queue (mutex + condition variable) per port */
#define _GNU_SOURCE
#include "queue.h"

#include <stdlib.h>
#include <string.h>

struct pkt *pkt_new(const struct frame *f)
{
    struct pkt *p = malloc(sizeof *p);
    if (p == NULL)
        return NULL;
    p->f = *f;
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

int queue_init(struct queue *q, int cap)
{
    memset(q, 0, sizeof *q);
    q->items = calloc((size_t)cap, sizeof *q->items);
    if (q->items == NULL)
        return -1;
    q->cap = cap;
    if (pthread_mutex_init(&q->lock, NULL) != 0) {
        free(q->items);
        return -1;
    }
    if (pthread_cond_init(&q->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&q->lock);
        free(q->items);
        return -1;
    }
    return 0;
}

void queue_destroy(struct queue *q)
{
    queue_drain(q);
    pthread_cond_destroy(&q->not_empty);
    pthread_mutex_destroy(&q->lock);
    free(q->items);
}

int queue_push(struct queue *q, struct pkt *p)
{
    pthread_mutex_lock(&q->lock);
    if (q->closing || q->count == q->cap) {
        q->dropped++;
        pthread_mutex_unlock(&q->lock);
        return -1;
    }
    q->items[q->tail] = p;
    q->tail = (q->tail + 1) % q->cap;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
    return 0;
}

struct pkt *queue_pop(struct queue *q)
{
    struct pkt *p;

    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->closing)
        pthread_cond_wait(&q->not_empty, &q->lock);
    if (q->closing) {
        pthread_mutex_unlock(&q->lock);
        return NULL;
    }
    p = q->items[q->head];
    q->head = (q->head + 1) % q->cap;
    q->count--;
    pthread_mutex_unlock(&q->lock);
    return p;
}

void queue_close(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    q->closing = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

void queue_drain(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    while (q->count > 0) {
        pkt_unref(q->items[q->head]);
        q->head = (q->head + 1) % q->cap;
        q->count--;
    }
    pthread_mutex_unlock(&q->lock);
}

void queue_reset(struct queue *q)
{
    pthread_mutex_lock(&q->lock);
    q->closing = 0;
    q->dropped = 0;
    q->head = 0;
    q->tail = 0;
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
