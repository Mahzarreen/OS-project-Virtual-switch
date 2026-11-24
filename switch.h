/* switch.h - the port structure and switch-wide state shared by all switch source files */
#ifndef SWITCH_H
#define SWITCH_H

#include <pthread.h>
#include <semaphore.h>
#include "queue.h"
#include "mactable.h"
#include "config.h"

struct port {
    int id;
    int used;
    int up;
    int fd;
    int vlan;
    int trunk;
    struct queue q;
    pthread_t tx;
    pthread_mutex_t lock;
};

extern struct port *ports;
extern int num_ports;
extern pthread_mutex_t ports_lock;
extern struct mac_table mac_table;
extern sem_t free_ports;
extern struct config cfg;

#endif
