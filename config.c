/* config.c - parses the "key value" config file into a struct config */
#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <string.h>

void config_defaults(struct config *c)
{
    c->mac_age = 30;
    c->mac_max = 1024;
    c->mac_per_port = 16;
    c->queue_size = 256;
    c->rate_limit = 1000;
    c->port_wait = 5;
    c->weights[0] = 5;
    c->weights[1] = 3;
    c->weights[2] = 1;
    c->trunk_port = -1;
    for (int i = 0; i < MAX_PORTS; i++)
    {
        c->port_vlan[i] = 1;
    }
}
static int parse_line(struct config *c, const char *line, int num_ports)
{
    char key[32];
    int a, b, d;
    if (sscanf(line, "%31s", key) != 1 || key[0] == '#')
    {
        return 0;
    }
    if (strcmp(key, "wrr") == 0) 
    {
        if (sscanf(line, "%*s %d %d %d", &a, &b, &d) != 3 || a < 1 || b < 1 || d < 1)
        {
            return -1;
        }
        c->weights[0] = a;
        c->weights[1] = b;
        c->weights[2] = d;
        return 0;
    }
    if (strcmp(key, "vlan") == 0) 
    {
        if (sscanf(line, "%*s %d %d", &a, &b) != 2 || a < 1 || a > num_ports || b < 1 || b > 4094)
            return -1;
        c->port_vlan[a - 1] = b;
        return 0;
    }
    if (sscanf(line, "%*s %d", &a) != 1)
    {
        return -1;
    }
    if (strcmp(key, "trunk") == 0) 
    {
        if (a < 0 || a > num_ports)
            return -1;
        c->trunk_port = a - 1;
    } 
    else if (strcmp(key, "mac_age") == 0 && a > 0) 
    {
        c->mac_age = a;
    } 
    else if (strcmp(key, "mac_max") == 0 && a > 0) 
    {
        c->mac_max = a;
    } 
    else if (strcmp(key, "mac_per_port") == 0 && a > 0) 
    {
        c->mac_per_port = a;
    } 
    else if (strcmp(key, "queue_size") == 0 && a > 0) 
    {
        c->queue_size = a;
    } 
    else if (strcmp(key, "rate_limit") == 0 && a >= 0)
    {
        c->rate_limit = a;
    } 
    else if (strcmp(key, "port_wait") == 0 && a > 0) 
    {
        c->port_wait = a;
    } else 
    {
        return -1;
    }
    return 0;
}
int config_load(struct config *c, const char *path, int num_ports)
{
    char line[256];
    int lineno = 0;
    int errors = 0;
    FILE *fp = fopen(path, "r");
    if (fp == NULL) 
    {
        perror(path);
        return -1;
    }
    while (fgets(line, sizeof line, fp) != NULL) 
    {
        lineno++;
        if (parse_line(c, line, num_ports) < 0) 
        {
            fprintf(stderr, "%s:%d: bad line: %s", path, lineno, line);
            errors++;
        }
    }
    fclose(fp);
    return errors ? -1 : 0;
}
