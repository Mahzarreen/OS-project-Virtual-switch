/* host.c - test host: sends frames typed on stdin and prints every frame it receives */
#define _GNU_SOURCE
#include "frame.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int sock;
static uint8_t my_mac[MAC_LEN];
static uint16_t my_vlan = 1;
static int frozen;
static pthread_mutex_t freeze_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t freeze_cond = PTHREAD_COND_INITIALIZER;

static void *receiver(void *arg)
{
    struct frame f;
    char src[18], dst[18];
    (void)arg;

    for (;;) 
    {
        int r;
        pthread_mutex_lock(&freeze_lock);
        while (frozen)
            pthread_cond_wait(&freeze_cond, &freeze_lock);
        pthread_mutex_unlock(&freeze_lock);
        r = read_frame(sock, &f);
        if (r <= 0) 
        {
            printf("disconnected from switch\n");
            fflush(stdout);
            exit(0);
        }
        mac_to_str(f.src, src);
        mac_to_str(f.dst, dst);
        printf("[recv] %s -> %s vlan %u prio %u: %.*s\n",src, dst, f.vlan, f.priority, (int)f.length, (char *)f.payload);
        fflush(stdout);
    }
    return NULL;
}
static void set_frozen(int value)
{
    pthread_mutex_lock(&freeze_lock);
    frozen = value;
    pthread_cond_signal(&freeze_cond);
    pthread_mutex_unlock(&freeze_lock);
    printf(value ? "stopped reading\n" : "reading again\n");
}
static int send_text(const char *dst, int prio, const char *text)
{
    struct frame f;
    size_t len = strlen(text);
    if (parse_mac(dst, f.dst) < 0) 
    {
        printf("bad mac: %s\n", dst);
        return 0;
    }
    if (len > MAX_PAYLOAD)
        len = MAX_PAYLOAD;
    memcpy(f.src, my_mac, MAC_LEN);
    f.length = (uint16_t)len;
    f.vlan = my_vlan;
    f.priority = (uint8_t)(prio < 0 || prio > 2 ? 1 : prio);
    memcpy(f.payload, text, len);

    if (write_frame(sock, &f) < 0) 
    {
        perror("write_frame");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    pthread_t tid;
    char line[2048];
    if (argc < 4) 
    {
        fprintf(stderr, "usage: %s <switch_ip> <tcp_port> <mac> [vlan]\n", argv[0]);
        return 1;
    }
    if (parse_mac(argv[3], my_mac) < 0) 
    {
        fprintf(stderr, "bad mac address\n");
        return 1;
    }
    if (argc > 4)
        my_vlan = (uint16_t)atoi(argv[4]);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) 
    {
        perror("signal");
        return 1;
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) 
    {
        perror("socket");
        return 1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) 
    {
        fprintf(stderr, "bad ip address\n");
        return 1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof addr) < 0) 
    {
        perror("connect");
        return 1;
    }
    if (pthread_create(&tid, NULL, receiver, NULL) != 0) 
    {
        fprintf(stderr, "pthread_create failed\n");
        return 1;
    }

    printf("connected. commands:\n");
    printf("  <dst_mac> <prio> <text>\n");
    printf("  spam <dst_mac> <prio> <count>\n");
    printf("  vlan <n>            (vlan field for frames sent from now on)\n");
    printf("  freeze | unfreeze   (stop/start reading, to test a slow host)\n");
    printf("  quit\n");
    fflush(stdout);

    while (fgets(line, sizeof line, stdin) != NULL) 
    {
        char dst[64], text[1600];
        int prio, count;
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, "quit") == 0)
            break;
        if (sscanf(line, "vlan %d", &count) == 1) 
        {
            my_vlan = (uint16_t)count;
            printf("sending on vlan %d\n", count);
            continue;
        }
        if (strcmp(line, "freeze") == 0) 
        {
            set_frozen(1);
            continue;
        }
        if (strcmp(line, "unfreeze") == 0) 
        {
            set_frozen(0);
            continue;
        }
        if (sscanf(line, "spam %63s %d %d", dst, &prio, &count) == 3) 
        {
            for (int i = 0; i < count; i++) 
            {
                snprintf(text, sizeof text, "msg %d", i);
                if (send_text(dst, prio, text) < 0)
                    break;
            }
        } 
        else if (sscanf(line, "%63s %d %1599[^\n]", dst, &prio, text) == 3) 
        {
            if (send_text(dst, prio, text) < 0)
                break;
        } 
        else if (line[0] != '\0') 
        {
            printf("unknown command\n");
        }
    }

    set_frozen(0);
    shutdown(sock, SHUT_RDWR);
    pthread_join(tid, NULL);
    close(sock);
    return 0;
}
