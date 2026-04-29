# Kernel Traffic Analyzer

Kernel Traffic Analyzer is a Linux network observability project that captures TCP/UDP traffic in a kernel module, exposes live connection data through `/proc`, enriches routes with a Python daemon, and displays everything in a Qt6 desktop GUI.

The project is designed for local system monitoring, learning kernel networking internals, and visualizing process-level network behavior.

## What It Does

- Tracks live TCP and UDP connections at kernel level.
- Maps traffic to processes, PIDs, UIDs, command names, and executable paths where possible.
- Detects DNS flows and maintains an IP-to-domain cache.
- Records per-process bandwidth, packet counts, connection state, and anomaly signals.
- Exposes traffic data through `/proc/traffic_analyzer*` files.
- Runs a Python route daemon that performs TCP traceroute and optional GeoIP enrichment.
- Provides a Qt6 GUI with tables, route maps, DNS views, anomaly views, history, cost tracking, firewall controls, trust scoring, and network performance views.

## Architecture

```text
┌──────────────────────────────────────────────┐
│ Qt6 GUI                                      │
│ Reads /proc data and displays live traffic   │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Kernel Module                                │
│ Netfilter hooks, packet parsing, stats, DNS  │
│ map, route queue, anomaly detection          │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│ Python Route Daemon                          │
│ Polls pending routes, runs traceroute,       │
│ writes enriched route hops back to /proc     │
└──────────────────────────────────────────────┘
```

## Project Structure

```text
kernel_traffic_analyzer/
├── start_kta.sh              # One-command launcher for the whole project
├── ta_route_daemon.py        # TCP traceroute + optional GeoIP route enrichment
├── README.md
├── kernel_module/
│   ├── Makefile
│   ├── include/              # Kernel module headers
│   └── src/                  # Netfilter hooks, packet parser, proc files, stats
└── gui/
    ├── CMakeLists.txt
    ├── main.cpp
    ├── core/                 # Data models, readers, DB, firewall, scoring logic
    └── ui/                   # Qt tabs, windows, widgets, theme, tray icon
```

## Requirements

This project is intended for Linux and must be run with root privileges because it builds and loads a kernel module.

Recommended environment:

- Ubuntu 22.04 or compatible Linux distribution
- Linux kernel headers for your running kernel
- GCC/G++ and Make
- CMake 3.22 or newer
- Qt6 development packages
- SQLite3 development package
- Python 3
- `traceroute` for route enrichment
- Optional: MaxMind GeoLite2 databases for city/ASN route metadata
- Optional: Python `geoip2` package

Install common dependencies on Ubuntu:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  linux-headers-$(uname -r) \
  cmake \
  qt6-base-dev \
  libsqlite3-dev \
  traceroute \
  python3 \
  python3-pip
```

Optional GeoIP support:

```bash
pip install geoip2 --break-system-packages
```

Place MaxMind databases here if you want route city/ASN enrichment:

```text
/usr/share/GeoIP/GeoLite2-City.mmdb
/usr/share/GeoIP/GeoLite2-ASN.mmdb
```

The project still works without GeoIP databases, but route metadata will be limited.

## Quick Start

Run the entire project with one file:

```bash
./start_kta.sh
```

The launcher automatically:

1. Re-runs itself with `sudo` if needed.
2. Builds the kernel module.
3. Unloads any older `traffic_analyzer` module instance.
4. Loads the freshly built module.
5. Starts `ta_route_daemon.py` when `traceroute` is available.
6. Configures and builds the Qt6 GUI.
7. Launches the GUI.
8. Stops the route daemon and unloads the kernel module when the GUI exits.

## Manual Build and Run

Use this only if you do not want the launcher script.

Build and load the kernel module:

```bash
cd kernel_module
make clean
make -j$(nproc)
sudo insmod traffic_analyzer.ko
```

Verify the module:

```bash
lsmod | grep traffic_analyzer
ls /proc/traffic_analyzer*
dmesg | tail -20
```

Start the route daemon:

```bash
sudo python3 ta_route_daemon.py --verbose
```

Build and run the GUI:

```bash
cmake -S gui -B gui/build -DCMAKE_BUILD_TYPE=Release
cmake --build gui/build -- -j$(nproc)
sudo -E gui/build/kernel_traffic_analyzer
```

Unload the module when finished:

```bash
sudo rmmod traffic_analyzer
```

## Kernel Module

The kernel module is located in `kernel_module/`.

Important source areas:

- `module_main.c`: module initialization and cleanup.
- `netfilter_hook.c`: registers IPv4/IPv6 local input and output hooks.
- `packet_parser.c`: parses IP, TCP, UDP, connection state, and packet metadata.
- `stats.c`: tracks connections, process aggregates, rates, and anomalies.
- `proc_interface.c`: creates the `/proc/traffic_analyzer*` files consumed by userspace.
- `dns_parser.c` and `dns_map.c`: parse DNS responses and map IPs to domains.
- `route_store.c`: stores route entries and pending route requests.
- `resolver.c`, `exe_resolver.c`, `sock_cache.c`, `inode_cache.c`, `flow_cache.c`: helper caches and async attribution logic.

The module exposes data through these `/proc` files:

```text
/proc/traffic_analyzer
/proc/traffic_analyzer_procs
/proc/traffic_analyzer_dns
/proc/traffic_analyzer_anomalies
/proc/traffic_analyzer_dns_map
/proc/traffic_analyzer_routes
/proc/traffic_analyzer_routes_pending
```

## Route Daemon

`ta_route_daemon.py` polls `/proc/traffic_analyzer_routes_pending`, runs TCP traceroute for remote destinations, enriches hops with GeoIP data when available, and writes results into `/proc/traffic_analyzer_routes`.

Run it manually with:

```bash
sudo python3 ta_route_daemon.py --verbose
```

Useful options:

```bash
sudo python3 ta_route_daemon.py --poll-interval 2
sudo python3 ta_route_daemon.py --city-db /path/to/GeoLite2-City.mmdb --asn-db /path/to/GeoLite2-ASN.mmdb
```

If `traceroute` or GeoIP files are missing, the GUI can still run, but the route map may show less detail.

## GUI

The GUI is located in `gui/` and is built with Qt6 and CMake.

Major GUI areas:

- `Connections`: live connection table with process, IP, domain, state, bytes, and rates.
- `Processes`: per-process traffic summary.
- `Route Map`: visual route paths and hop details.
- `DNS`: DNS cache entries observed by the kernel.
- `Anomalies`: process/network anomaly events.
- `Bandwidth Load`: bandwidth usage by process.
- `Timeline`: connection timeline visualization.
- `History`: SQLite-backed historical bandwidth views.
- `Data Cost`: estimated usage cost tracking.
- `DNS Leaks`: compares DNS traffic against configured resolvers.
- `BGP Monitor`: route fingerprint monitoring.
- `Threat Map`: heuristic risk display for remote IPs.
- `Firewall`: iptables-based blocking controls.
- `Trust`: process trust grading.
- `Net Perf`: RTT, jitter, and packet loss display.

The GUI reads directly from `/proc/traffic_analyzer*`, so the kernel module must be loaded before the interface can show live data.

## Troubleshooting

Kernel headers missing:

```bash
sudo apt install linux-headers-$(uname -r)
```

Qt6 package missing:

```bash
sudo apt install qt6-base-dev
```

Module is already loaded:

```bash
sudo rmmod traffic_analyzer
sudo insmod kernel_module/traffic_analyzer.ko
```

No `/proc/traffic_analyzer*` files:

```bash
dmesg | tail -50
lsmod | grep traffic_analyzer
```

GUI cannot open when run with sudo:

```bash
sudo -E ./start_kta.sh
```

Route map is empty:

```bash
sudo apt install traceroute
sudo python3 ta_route_daemon.py --verbose
```

GeoIP fields are missing:

- Install `geoip2`.
- Download MaxMind GeoLite2 City and ASN databases.
- Place them under `/usr/share/GeoIP/`.

## Development Notes

- Build artifacts are intentionally ignored by `.gitignore`.
- Generated kernel files such as `*.ko`, `*.o`, `*.cmd`, `Module.symvers`, and `modules.order` should not be committed.
- GUI build output lives in `gui/build/`.
- The one-file launcher is `start_kta.sh`; keep it executable.
- Root privileges are expected for module loading, route daemon writes, and firewall features.

## Safety

This project loads a custom kernel module and hooks into local network packet handling. Use it on a development machine or VM first. If the module fails to unload, close the GUI and daemon, then run:

```bash
sudo rmmod traffic_analyzer
```

## Author

Anil Reddy
