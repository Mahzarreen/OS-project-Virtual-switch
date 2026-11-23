/* frame.h - the fixed frame format and helpers to send and receive whole frames */
#ifndef FRAME_H
#define FRAME_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#define MAC_LEN 6
#define HDR_LEN 17
#define MAX_PAYLOAD 1500

struct frame {
    uint16_t length;
    uint8_t src[MAC_LEN];
    uint8_t dst[MAC_LEN];
    uint16_t vlan;
    uint8_t priority;
    uint8_t payload[MAX_PAYLOAD];
};

ssize_t read_full(int fd, void *buf, size_t n);
ssize_t write_full(int fd, const void *buf, size_t n);
int read_frame(int fd, struct frame *f);
int write_frame(int fd, const struct frame *f);

int parse_mac(const char *s, uint8_t mac[MAC_LEN]);
void mac_to_str(const uint8_t mac[MAC_LEN], char *buf);
int is_broadcast(const uint8_t mac[MAC_LEN]);

#endif
