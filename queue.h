/* queue.h - shared frames with a reference count and the bounded per-port output queue */
#ifndef QUEUE_H
#define QUEUE_H
#include <pthread.h>
#include "frame.h"

struct pkt 
{
    struct frame f;
    int refcount;
    pthread_mutex_t lock;
};

struct queue 
{
    struct pkt **items;
    int cap;
    int head;
    int tail;
    int count;
    int closing;
    unsigned long dropped;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
};

struct pkt *pkt_new(const struct frame *f);
void pkt_ref(struct pkt *p);
void pkt_unref(struct pkt *p);
int queue_init(struct queue *q, int cap);
void queue_destroy(struct queue *q);
int queue_push(struct queue *q, struct pkt *p);
struct pkt *queue_pop(struct queue *q);
void queue_close(struct queue *q);
void queue_drain(struct queue *q);
void queue_reset(struct queue *q);
unsigned long queue_dropped(struct queue *q);

#endif
