/* admin.h - the UNIX socket path used by swctl and the admin thread inside the switch */
#ifndef ADMIN_H
#define ADMIN_H

#define ADMIN_SOCKET "/tmp/vswitch.sock"

int admin_start(void);
void admin_stop(void);

#endif
