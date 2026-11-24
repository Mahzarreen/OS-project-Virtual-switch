/* config.h - switch settings with defaults, optionally read from a config file */
#ifndef CONFIG_H
#define CONFIG_H

#define MAX_PORTS 64

struct config 
{
    int mac_age;
    int mac_max;
    int mac_per_port;
    int queue_size;
    int rate_limit;
    int port_wait;
    int weights[3];
    int trunk_port;
    int port_vlan[MAX_PORTS];
};

void config_defaults(struct config *c);
int config_load(struct config *c, const char *path, int num_ports);

#endif
