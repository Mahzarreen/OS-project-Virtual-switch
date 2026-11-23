# Makefile - builds the switch, the test host, and a ThreadSanitizer build of the switch
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -g -O0 -pthread

SWITCH_SRC = switch.c frame.c
HOST_SRC = host.c frame.c

all: switch host

switch: $(SWITCH_SRC) frame.h
	$(CC) $(CFLAGS) -o $@ $(SWITCH_SRC)

host: $(HOST_SRC) frame.h
	$(CC) $(CFLAGS) -o $@ $(HOST_SRC)

tsan: $(SWITCH_SRC) frame.h
	$(CC) $(CFLAGS) -fsanitize=thread -o switch_tsan $(SWITCH_SRC)

clean:
	rm -f switch host switch_tsan

.PHONY: all clean tsan
