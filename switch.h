/* switch.h - the port structure and switch-wide settings shared by all switch source files */
#ifndef SWITCH_H
#define SWITCH_H
#include <pthread.h>
#include "queue.h"
#define QUEUE_CAP 256

struct port 
{
    int id;
    int used;
    int up;
    int fd;
    struct queue q;
    pthread_t tx;
    pthread_mutex_t lock;
};

extern struct port *ports;
extern int num_ports;
extern pthread_mutex_t ports_lock;

#endif
