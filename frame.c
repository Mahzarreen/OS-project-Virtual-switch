/* frame.c - packs/unpacks the 17-byte header and loops over partial reads and writes */
#define _GNU_SOURCE
#include "frame.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

ssize_t read_full(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) 
    {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r == 0)
            return 0;
        if (r < 0) 
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

ssize_t write_full(int fd, const void *buf, size_t n)
{
    size_t done = 0;
    while (done < n) 
    {
        ssize_t w = write(fd, (const char *)buf + done, n - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        done += (size_t)w;
    }
    return (ssize_t)done;
}

int read_frame(int fd, struct frame *f)
{
    uint8_t hdr[HDR_LEN];
    uint16_t v;
    ssize_t r;
    r = read_full(fd, hdr, HDR_LEN);
    if (r <= 0)
    {
        return (int)r;
    }
    memcpy(&v, hdr, 2);
    f->length = ntohs(v);
    memcpy(f->src, hdr + 2, MAC_LEN);
    memcpy(f->dst, hdr + 8, MAC_LEN);
    memcpy(&v, hdr + 14, 2);
    f->vlan = ntohs(v);
    f->priority = hdr[16];
    if (f->length > MAX_PAYLOAD)
    {
        return -1;
    }
    if (f->priority > 2)
    {
        f->priority = 2;
    }
    if (f->length > 0)
    {
        r = read_full(fd, f->payload, f->length);
        if (r <= 0)
        {
            return (int)r;
        }
    }
    return 1;
}

int write_frame(int fd, const struct frame *f)
{
    uint8_t buf[HDR_LEN + MAX_PAYLOAD];
    uint16_t v;
    if (f->length > MAX_PAYLOAD)
    {
        return -1;
    }
    v = htons(f->length);
    memcpy(buf, &v, 2);
    memcpy(buf + 2, f->src, MAC_LEN);
    memcpy(buf + 8, f->dst, MAC_LEN);
    v = htons(f->vlan);
    memcpy(buf + 14, &v, 2);
    buf[16] = f->priority;
    memcpy(buf + HDR_LEN, f->payload, f->length);
    if (write_full(fd, buf, HDR_LEN + f->length) < 0)
    {
        return -1;
    }
    return 0;
}

int parse_mac(const char *s, uint8_t mac[MAC_LEN])
{
    unsigned int b[MAC_LEN];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
    {
        return -1;
    }
    for (int i = 0; i < MAC_LEN; i++)
    {
        if (b[i] > 0xff)
            return -1;
        mac[i] = (uint8_t)b[i];
    }
    return 0;
}

void mac_to_str(const uint8_t mac[MAC_LEN], char *buf)
{
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int is_broadcast(const uint8_t mac[MAC_LEN])
{
    for (int i = 0; i < MAC_LEN; i++)
    {
        if (mac[i] != 0xff)
        {
            return 0;
        }
    }
    return 1;
}
