/* switch.h - the port structure and switch-wide settings shared by all switch source files */
#ifndef SWITCH_H
#define SWITCH_H

#include <pthread.h>
#include <semaphore.h>
#include "queue.h"
#include "mactable.h"
#define QUEUE_CAP 256
#define MAC_MAX_ENTRIES 1024
#define MAC_PER_PORT 16
#define MAC_AGE_SEC 30
#define PORT_WAIT_SEC 5

struct port {
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
extern struct mac_table mac_table;
extern sem_t free_ports;

#endif
