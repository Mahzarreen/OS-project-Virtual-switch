/* admin.c - admin thread: accepts swctl connections on a UNIX socket and runs one command each */
#define _GNU_SOURCE
#include "admin.h"
#include "switch.h"
#include "logger.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int listen_fd = -1;
static pthread_t admin_tid;

static void run_command(const char *line, FILE *out)
{
    int a, b;
    if (strcmp(line, "show mac") == 0) 
    {
        mac_dump(&mac_table, out);
    }
    else if (strcmp(line, "show ports") == 0) 
    {
        port_show(out);
    } 
    else if (strcmp(line, "clear mac") == 0) 
    {
        mac_clear(&mac_table);
        fprintf(out, "mac table cleared\n");
    } 
    else if (sscanf(line, "shutdown %d", &a) == 1) 
    {
        if (port_shutdown(a - 1) < 0)
            fprintf(out, "bad port %d\n", a);
        else
            fprintf(out, "port %d shut down\n", a);
    } 
    else if (sscanf(line, "up %d", &a) == 1) 
    {
        if (port_enable(a - 1) < 0)
            fprintf(out, "bad port %d\n", a);
        else
            fprintf(out, "port %d enabled\n", a);
    } 
    else if (sscanf(line, "vlan %d %d", &a, &b) == 2) 
    {
        if (port_set_vlan(a - 1, b) < 0)
            fprintf(out, "bad port or vlan\n");
        else
            fprintf(out, "port %d is now in vlan %d\n", a, b);
    } 
    else if (sscanf(line, "mirror %d %d", &a, &b) == 2) 
    {
        if (port_set_mirror(a - 1, b - 1) < 0)
            fprintf(out, "bad port numbers\n");
        else if (b == 0)
            fprintf(out, "mirroring of port %d stopped\n", a);
        else
            fprintf(out, "port %d mirrored to port %d\n", a, b);
    } 
    else 
    {
        fprintf(out, "unknown command: %s\n", line);
    }
}
static void handle_client(int c)
{
    char line[256];
    size_t got = 0;
    char *reply = NULL;
    size_t len = 0;
    FILE *out;
    while (got < sizeof line - 1) 
    {
        ssize_t r = read(c, line + got, sizeof line - 1 - got);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    line[got] = '\0';
    line[strcspn(line, "\n")] = '\0';
    out = open_memstream(&reply, &len);
    if (out == NULL) 
    {
        perror("open_memstream");
        return;
    }
    log_msg("admin: %s", line);
    run_command(line, out);
    fclose(out);
    if (write_full(c, reply, len) < 0)
        perror("admin reply");
    free(reply);
}

static void *admin_thread(void *arg)
{
    (void)arg;
    for (;;) 
    {
        int c = accept(listen_fd, NULL, NULL);
        if (c < 0) 
        {
            if (errno == EINTR)
                continue;
            break;
        }
        handle_client(c);
        close(c);
    }
    return NULL;
}
int admin_start()
{
    struct sockaddr_un addr;
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) 
    {
        perror("admin socket");
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ADMIN_SOCKET, sizeof addr.sun_path - 1);
    if (unlink(ADMIN_SOCKET) < 0 && errno != ENOENT)
    {
        perror("unlink admin socket");
    }
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) 
    {
        perror("admin bind");
        close(listen_fd);
        return -1;
    }
    if (listen(listen_fd, 8) < 0)
    {
        perror("admin listen");
        close(listen_fd);
        return -1;
    }
    if (pthread_create(&admin_tid, NULL, admin_thread, NULL) != 0) 
    {
        fprintf(stderr, "cannot start admin thread\n");
        close(listen_fd);
        return -1;
    }
    return 0;
}
void admin_stop()
{
    shutdown(listen_fd, SHUT_RDWR);
    pthread_join(admin_tid, NULL);
    close(listen_fd);
    unlink(ADMIN_SOCKET);
}
