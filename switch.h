/* switch.h - the port structure, port operations used by the admin thread, and shared switch state */
#ifndef SWITCH_H
#define SWITCH_H

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include "queue.h"
#include "mactable.h"
#include "config.h"

#define LOG_FILE "switch.log"
#define MAC_DUMP_FILE "mac_dump.txt"

enum { PORT_FREE, PORT_BUSY, PORT_DONE };

struct port {
    int id;
    int state;
    int disabled;
    int up;
    int fd;
    int vlan;
    int trunk;
    int mirror_to;
    struct queue q;
    pthread_t tx;
    pthread_t rx;
    pthread_mutex_t lock;
};

extern struct port *ports;
extern int num_ports;
extern pthread_mutex_t ports_lock;
extern struct mac_table mac_table;
extern sem_t free_ports;
extern struct config cfg;

int port_shutdown(int idx);
int port_enable(int idx);
int port_set_vlan(int idx, int vlan);
int port_set_mirror(int idx, int target);
void port_show(FILE *out);

#endif
