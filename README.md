# Kernel Traffic Analyzer

Kernel Traffic Analyzer is a Linux desktop tool for observing which local processes generate TCP and UDP traffic from a kernel Netfilter vantage point.

## What It Does

- Hooks IPv4 and IPv6 local input/output traffic in a kernel module.
- Attributes connections to PID, UID, command name, and executable path where possible.
- Exposes live connections, process totals, DNS mappings, anomalies, and routes through `/proc/traffic_analyzer*`.
- Uses a Python route daemon to run TCP traceroute for pending remote destinations.

## Architecture

```text
Kernel Netfilter hooks
       |
packet_parser.c -> stats.c -> proc_interface.c
                                    |
                    /proc/traffic_analyzer*    <--- ta_route_daemon.py
                                    |                      ^
                    ProcReader::readAll()          traceroute subprocess
                                    |                      ^
                    QAbstractTableModel           /proc/traffic_analyzer_routes_pending
                                    |
                    Qt6 Widgets tables
```

## eBPF/XDP Extension Blueprint

The planned high-throughput stack is documented in
[`docs/ebpf_xdp_feature_stack.md`](docs/ebpf_xdp_feature_stack.md). It covers six
implementation-level features for extending this project with XDP/eBPF capture,
AF_PACKET `PACKET_MMAP`, BPF flow maps, C++ protocol dissection, live dashboard
IPC, DPI prefiltering, and TCP stream reconstruction while preserving the current
Netfilter process-attribution path.

## Requirements

- Linux with headers for the running kernel
- GCC/G++ and Make
- CMake 3.22 or newer
- Qt6 Core, Gui, and Widgets development packages
- SQLite3 development package
- Python 3
- `traceroute` for route collection
- Optional: Clang/LLVM and libbpf development headers for building the eBPF
  XDP/TC object in `bpf/kta_xdp_tc.bpf.c`
- Optional: Python `geoip2` plus MaxMind GeoLite2 City and ASN databases

Ubuntu packages:

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) cmake \
  qt6-base-dev libsqlite3-dev traceroute python3 python3-pip \
  clang llvm libbpf-dev
```

Optional GeoIP:

```bash
pip install geoip2 --break-system-packages
```

## Quick Start

```bash
./start_kta.sh
```

The launcher rebuilds the kernel module and GUI, loads `traffic_analyzer.ko`, starts the route daemon when `traceroute` is available, launches the GUI, and cleans up when the GUI exits.

## Manual Build

Kernel module:

```bash
cd kernel_module
make clean
make -j$(nproc)
sudo insmod traffic_analyzer.ko
```

Route daemon:

```bash
sudo python3 ta_route_daemon.py --poll-interval 2
```

GUI:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j$(nproc)
sudo -E build/gui/kernel_traffic_analyzer
```

AF_PACKET backend:

```bash
cmake --build build --target kta_packet_backend -- -j$(nproc)
build/backend/kta_packet_backend --self-test
sudo build/backend/kta_packet_backend --interface any --interval-ms 1000
```

The backend uses `TPACKET_V3` packet mmap rings, performs Ethernet/VLAN/IP/TCP/UDP
dissection, tracks flows, emits lightweight DPI hints for DNS/HTTP/TLS, and
prints live JSON snapshots suitable for GUI or daemon integration.

eBPF fast-path object:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c bpf/kta_xdp_tc.bpf.c -o build/kta_xdp_tc.bpf.o
```

The BPF source defines the XDP flow map, per-CPU protocol counters, and ring-buffer
packet metadata event used by the high-throughput design. Loading/attaching this
object with libbpf is the next integration step; the AF_PACKET backend is the
currently runnable capture path.

Unload:

```bash
sudo rmmod traffic_analyzer
```

## `/proc` Files

- `/proc/traffic_analyzer`: live connection rows with process, protocol, endpoints, state, bytes, rates, and timestamps.
- `/proc/traffic_analyzer_procs`: per-process aggregate connection and bandwidth rows.
- `/proc/traffic_analyzer_dns`: DNS traffic rows observed in the connection table.
- `/proc/traffic_analyzer_anomalies`: process anomaly rows derived from kernel statistics.
- `/proc/traffic_analyzer_dns_map`: DNS response mappings from IP address to domain.
- `/proc/traffic_analyzer_routes`: completed or pending route rows with hop data.
- `/proc/traffic_analyzer_routes_pending`: route requests consumed by `ta_route_daemon.py`.

## Safety Note

This project loads a kernel module and must be run as root for module operations. Use it on development machines or systems where you are comfortable building and loading local kernel code. The GUI is an observability interface; it does not manage firewall rules or make outbound network requests.
