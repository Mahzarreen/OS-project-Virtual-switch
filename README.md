# Virtual Switch (Operating Systems, Fall 2026)

A software network switch in C. The switch is a multithreaded server; each host is a separate
client process connected over TCP, and an admin tool (`swctl`) controls the switch while it runs.

## Building

```bash
make            # builds switch, host and swctl
make tsan       # builds switch_tsan (switch compiled with -fsanitize=thread)
make clean      # removes all built programs
```

Everything is compiled with `gcc -std=c11 -Wall -Wextra -Werror -g -O0`.

## Running

### The switch

```bash
./switch <tcp_port> <num_ports> [config_file]
./switch 9000 4 switch.conf
```

`num_ports` can be 1 to 64. The config file is optional; without it the defaults below are used.
The switch writes its log to `switch.log` (and echoes it to the terminal).

### A test host

```bash
./host <switch_ip> <tcp_port> <mac> [vlan]
./host 127.0.0.1 9000 02:00:00:00:00:0a
```

Commands typed into a host:

| Command | Meaning |
|---|---|
| `<dst_mac> <prio> <text>` | send one frame (prio 0 = high, 1 = normal, 2 = low) |
| `spam <dst_mac> <prio> <count>` | send `count` frames quickly |
| `vlan <n>` | set the vlan field of frames sent from now on (used on the trunk port) |
| `freeze` / `unfreeze` | stop / start reading frames, to simulate a slow host |
| `quit` | disconnect |

Use `ff:ff:ff:ff:ff:ff` as the destination for a broadcast.

### The admin tool

```bash
./swctl show mac
./swctl show ports
./swctl shutdown <port>
./swctl up <port>
./swctl vlan <port> <vlan>
./swctl mirror <port> <sniffer_port>     # sniffer_port 0 stops mirroring
./swctl clear mac
./swctl stats
./swctl stats --watch                     # refreshes every second, Enter to quit
```

Ports are numbered from 1. `swctl` talks to the switch over the UNIX socket `/tmp/vswitch.sock`;
`stats` reads the counters directly from the shared memory object `/vswitch_stats`.

### Signals

| Signal | Effect |
|---|---|
| `SIGINT` (Ctrl+C) or `SIGTERM` | clean shutdown: all threads joined, sockets closed, memory freed |
| `SIGHUP` | reload the config file without restarting |
| `SIGUSR1` | write the MAC table to `mac_dump.txt` |

```bash
kill -HUP <pid>       # the pid is printed in the first log line
kill -USR1 <pid>
```

## Config file format

One setting per line, `key value`. Lines starting with `#` and empty lines are ignored.

| Key | Default | Meaning |
|---|---|---|
| `mac_age <seconds>` | 30 | MAC entries not seen for this long are removed |
| `mac_max <n>` | 1024 | maximum MAC table size (least recently used entry is evicted) |
| `mac_per_port <n>` | 16 | port security: more MACs than this on one port disables the port |
| `queue_size <n>` | 256 | size of each priority queue of a port (needs a restart to change) |
| `rate_limit <n>` | 1000 | frames per second each port may send, 0 = unlimited |
| `port_wait <seconds>` | 5 | how long an extra host waits for a free port before "switch full" |
| `wrr <high> <normal> <low>` | 5 3 1 | weighted round robin weights |
| `vlan <port> <vlan>` | 1 | VLAN of a port (1 to 4094); can appear once per port |
| `trunk <port>` | none | the trunk port; `trunk 0` means no trunk |

Example (`switch.conf`):

```
rate_limit 1000
wrr 5 3 1
vlan 1 10
vlan 2 10
vlan 3 20
trunk 4
```

On `SIGHUP` every setting except `queue_size` is applied to the running switch. If the file has
an error, the switch keeps the old config and logs which line was wrong.

## Notes

- A port disabled by `swctl shutdown` or by port security gets no new hosts until `swctl up`.
- If every enabled port is taken, a new host waits `port_wait` seconds, then receives a frame
  with the text `switch full` and is disconnected.
- A host that arrives when the only free ports are disabled ones is rejected straight away.

## Completed items

- Tier 1: items 1 to 5
- Tier 2: items 6 to 13
- Tier 3: not attempted
