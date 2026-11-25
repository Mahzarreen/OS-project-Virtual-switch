# Makefile - builds the switch, the test host, the swctl admin tool, and a ThreadSanitizer build of the switch
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -g -O0 -pthread
LDLIBS = -lrt

SWITCH_SRC = switch.c queue.c mactable.c config.c stats.c admin.c frame.c
SWITCH_HDR = switch.h queue.h mactable.h config.h stats.h admin.h frame.h
HOST_SRC = host.c frame.c
SWCTL_SRC = swctl.c stats.c

all: switch host swctl

switch: $(SWITCH_SRC) $(SWITCH_HDR)
	$(CC) $(CFLAGS) -o $@ $(SWITCH_SRC) $(LDLIBS)

host: $(HOST_SRC) frame.h
	$(CC) $(CFLAGS) -o $@ $(HOST_SRC)

swctl: $(SWCTL_SRC) stats.h admin.h config.h
	$(CC) $(CFLAGS) -o $@ $(SWCTL_SRC) $(LDLIBS)

tsan: $(SWITCH_SRC) $(SWITCH_HDR)
	$(CC) $(CFLAGS) -fsanitize=thread -o switch_tsan $(SWITCH_SRC) $(LDLIBS)

clean:
	rm -f switch host swctl switch_tsan

.PHONY: all clean tsan
