# Kernel Traffic Analyzer (KTA) v6.0

A production-grade Linux network observability system that tracks every TCP/UDP connection at the kernel level, enriches it with DNS resolution, geographic routing, and anomaly detection, and presents everything in a live Qt6 GUI.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Qt6 GUI (C++)                         │
│  15 tabs: Connections, Processes, Route Map, DNS,        │
│  Anomalies, Bandwidth, Timeline, History, Cost,          │
│  DNS Leaks, BGP Monitor, Threat Map, Firewall, Trust,    │
│  Net Perf                                                │
└────────────────────┬────────────────────────────────────┘
                     │ reads /proc files every 1 second
┌────────────────────▼────────────────────────────────────┐
│              Kernel Module (C) — v6.0                    │
│  7 /proc files, netfilter hooks, DNS parser,             │
│  anomaly detection, route store                          │
└────────────────────┬────────────────────────────────────┘
                     │ route requests / hop writes
┌────────────────────▼────────────────────────────────────┐
│         Route Daemon (Python3)                           │
│  TCP traceroute + MaxMind GeoLite2 enrichment            │
└─────────────────────────────────────────────────────────┘
```

---

## System Requirements

- Ubuntu 22.04
- Kernel 6.8.0-106-generic (or compatible)
- Qt6 (Core, Gui, Widgets, PrintSupport, Network)
- CMake 3.22+
- GCC/G++
- Python 3.10+
- `traceroute` (`sudo apt install traceroute`)
- MaxMind GeoLite2 databases (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`) at `/usr/share/GeoIP/`
- SQLite3 (`sudo apt install libsqlite3-dev`)
- `geoip2` Python package (`pip install geoip2`)

---

## Quick Start

```bash
# One command does everything
sudo ~/Documents/Projects/kernel_traffic_analyzer/start_kta.sh
```

The script automatically: unloads any old module, rebuilds kernel module, reloads it, rebuilds the GUI, starts the route daemon, and launches the GUI. On GUI exit it stops the daemon and unloads the module cleanly.

---

## Project Structure

```
kernel_traffic_analyzer/
├── kernel_module/
│   ├── src/
│   │   ├── module_main.c       — module init/cleanup
│   │   ├── netfilter_hook.c    — LOCAL_IN/LOCAL_OUT hooks
│   │   ├── packet_parser.c     — IP/TCP/UDP header parsing
│   │   ├── stats.c             — connection tracking, anomaly detection
│   │   ├── proc_interface.c    — 7 /proc file implementations
│   │   ├── dns_parser.c        — wire-format DNS response parser
│   │   ├── dns_map.c           — IP→domain cache
│   │   ├── route_store.c       — route hash table, pending queue
│   │   ├── flow_cache.c        — fast connection lookup
│   │   ├── sock_cache.c        — socket→PID mapping
│   │   ├── exe_resolver.c      — process exe path resolution
│   │   └── resolver.c          — async exe/PID resolver workqueue
│   └── include/
│       └── traffic_analyzer.h  — shared structs, anomaly flags, tunables
│
├── gui/
│   ├── CMakeLists.txt
│   ├── main.cpp
│   ├── core/
│   │   ├── TrafficEntry.h      — 22-col connection struct + RateHistory
│   │   ├── ProcEntry.h         — per-process struct + AnomalyType
│   │   ├── RouteEntry.h        — RouteHop + RouteEntry
│   │   ├── DnsEntry.h          — DNS map entry
│   │   ├── AnomalyEntry.h      — anomaly event struct
│   │   ├── ProcReader.cpp      — reads all 7 /proc files
│   │   ├── TrafficModel.cpp    — QAbstractTableModel + sparkline data
│   │   ├── ProcModel.cpp       — QAbstractTableModel for processes
│   │   ├── HistoryDB.cpp       — SQLite3 bandwidth history
│   │   ├── CostTracker.cpp     — ₹/GB cost calculation
│   │   ├── DnsLeakDetector.cpp — resolv.conf vs actual DNS comparison
│   │   ├── BgpMonitor.cpp      — route fingerprint change detection
│   │   ├── FirewallManager.cpp — iptables OUTPUT rule management
│   │   ├── BandwidthThrottler.cpp — tc-based per-process limits
│   │   ├── ThreatIntel.cpp     — heuristic IP threat scoring
│   │   ├── TrustScorer.cpp     — per-process trust grading (A–F)
│   │   └── Exporter.cpp        — JSON / CSV / PDF export
│   └── ui/
│       ├── Style.h             — full dark theme QSS
│       ├── Sidebar.h/.cpp      — collapsible sidebar, 15 nav buttons
│       ├── MainWindow.h/.cpp   — QStackedWidget, 1s refresh timer
│       ├── ConnectionsTab      — live connection table with sparklines
│       ├── ProcessesTab        — per-process view, anomaly highlighting
│       ├── RouteMapWidget      — hand-drawn world map, animated arcs
│       ├── DnsTab              — DNS entry table, TTL color coding
│       ├── AnomalyTab          — anomaly event log
│       ├── LoadBalancerTab     — bandwidth bars per process
│       ├── ProcessDetailOverlay — full-screen process drill-down
│       ├── HistoryTab          — 1h/24h/7d bandwidth graphs
│       ├── CostTab             — ₹/GB data cost tracker
│       ├── TimelineTab         — Gantt-style connection timeline
│       ├── DnsLeakTab          — DNS leak detection UI
│       ├── BgpTab              — BGP route change monitor
│       ├── ThreatMapTab        — world map with threat-scored IPs
│       ├── FireWallTab         — iptables block + tc throttle UI
│       ├── TrustTab            — process trust scoring table
│       ├── NetworkPerfTab      — live RTT/jitter/packet-loss graphs
│       ├── AlertPopup          — slide-in anomaly alert, 8s auto-dismiss
│       └── TrayIcon            — system tray with anomaly badge
│
└── ta_route_daemon.py          — TCP traceroute + GeoIP route enrichment
```

---

## Kernel Module — Phase Details

### Phase 1 — Connection Tracking
Netfilter hooks on `NF_INET_LOCAL_OUT` and `NF_INET_LOCAL_IN` capture every TCP/UDP packet. Connections are stored in a linked list (max 2048 entries) keyed by canonical 4-tuple `(src_ip, src_port, dst_ip, dst_port)`. Per-entry state machine advances through `SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED`. Entries expire based on TTL per state.

### Phase 2 — Per-Process Attribution
A socket→PID cache (`sock_cache`) maps kernel sockets to PIDs. A workqueue resolver (`ta_resolver`) calls `d_path()` to get the executable path — this is done asynchronously to avoid blocking in softirq context. Stack frames are kept under 1024 bytes throughout.

### Phase 3 — Bandwidth Rates
A 1-second sliding window rate tracker updates `rate_out_bps` and `rate_in_bps` per connection. The GUI ring buffer (`RateHistory`, 30 samples) feeds sparkline delegates in the connections table.

### Phase 4 — DNS Resolution
DNS responses (UDP src port 53) are intercepted in the incoming hook before `parse_packet()` runs. A wire-format parser extracts A/AAAA records and populates the IP→domain cache. This means `domain` is available immediately on the connection entry when it is created.

### Phase 5 — Route Tracing
When a new TCP connection is established to a routable IP, `route_store_request()` adds it to `/proc/traffic_analyzer_routes_pending`. The Python route daemon polls this file every 2 seconds, runs `traceroute -T -p 443` (TCP mode, works through NAT and mobile hotspots), enriches each hop with MaxMind GeoLite2 city and ASN data, and writes results back to `/proc/traffic_analyzer_routes`.

### Phase 6 — Anomaly Detection
Five anomaly types are detected per process: `PORT_SCAN` (15+ unique dest ports/sec), `SYN_FLOOD` (SYN pending ratio ≥ 80%), `CONN_BURST` (20+ new connections/sec), `HIGH_CONNS` (200+ total), `HIGH_BW` (10+ MB/s). Known system tools (`traceroute`, `ping`, `curl`, `wget`) are whitelisted from SYN flood detection.

---

## /proc File Contract

All column orders are fixed — the GUI depends on exact indices.

```
/proc/traffic_analyzer          — live connections (22 cols)
/proc/traffic_analyzer_procs    — per-process aggregates (22 cols)
/proc/traffic_analyzer_dns      — DNS query flows
/proc/traffic_analyzer_anomalies — anomaly events (11 cols)
/proc/traffic_analyzer_dns_map  — IP→domain cache (7 cols)
/proc/traffic_analyzer_routes   — route hops with geo (15 cols per hop)
/proc/traffic_analyzer_routes_pending — daemon work queue (R/W)
```

Key column indices:

```
traffic_analyzer:
  0=PID 1=UID 2=PROCESS 3=RESOLVED 4=STATE 5=DNS 6=PROTO
  7=SRC_IP 8=DEST_IP 9=SRC_PORT 10=DEST_PORT 11=DOMAIN
  12=OUT_BYTES 13=IN_BYTES 16=RATE_OUT_BPS 17=RATE_IN_BPS

traffic_analyzer_routes (per hop):
  0=DEST_IP 1=DOMAIN 2=STATUS 3=TOTAL_HOPS 4=HOP_N
  5=HOP_IP 6=HOST 7=RTT_MS 8=CITY 9=COUNTRY 10=CC
  11=LAT_E6 12=LON_E6 13=ASN 14=ORG
  (LAT_E6/LON_E6 ÷ 1,000,000 = degrees)
```

---

## GUI — Tab Reference

| Tab | What it shows |
|-----|--------------|
| Connections | Live table of all TCP/UDP connections with 30s sparklines on IN/OUT columns. Filter by process, domain, IP, or state. Click row → detail panel. |
| Processes | Per-process aggregated bandwidth, connection counts, anomaly status. Red rows = active anomaly. Click → Process Detail Overlay. |
| Route Map | Hand-drawn dark world map. Animated packet dots travel along traceroute arcs from Bhopal to each destination. Bottom legend bar shows all active connections. Left panel shows data sovereignty path and latency blame hop. |
| DNS Map | All DNS entries seen by the kernel. TTL color coded: green > 60s, amber > 10s, red expiring. |
| Anomalies | Live anomaly event log. Alert popup slides in from bottom-right on new detection, auto-dismisses after 8 seconds. |
| Bandwidth Load | All processes sorted by total bandwidth, highest first. Visual OUT (blue) and IN (green) gradient bars. Click → Process Detail Overlay. |
| Timeline | Gantt-style horizontal bars showing when each connection was open/closed over the last 30 minutes. Filter by TCP/UDP/Active. |
| History | 1-hour and 24-hour line graphs + 7-day bar chart per process from SQLite history. |
| Data Cost | Configurable ₹/GB ISP rate. Shows cost per process today, this week, and monthly total with usage progress bar. |
| DNS Leaks | Compares actual DNS destinations against `/etc/resolv.conf` authorized resolvers. Flags any process querying external port 53 directly. |
| BGP Monitor | Learns normal ASN/country path per domain over 7 days. Alerts when packet path changes country unexpectedly. |
| Threat Map | World map with IPs scored by heuristic threat level. Warm arcs = suspicious/Tor exit ranges. Table shows only flagged IPs. |
| Firewall | Lists active connections with one-click iptables OUTPUT block. Firewall rules table with unblock buttons. Bandwidth throttle tab using `tc`. |
| Trust | Grades every process A–F based on exe path, anomaly history, connection count, and bandwidth. Red rows = grade F. |
| Net Perf | Live RTT, jitter, and packet loss graph using continuous TCP ping to `8.8.8.8`. |

### Process Detail Overlay
Full-screen overlay opened from Processes tab or Bandwidth Load tab. Shows: stat cards (connections, rates, total data, anomaly status), 5-minute bandwidth graph, active connections table, DNS queries table, and a mini geographic route map for that process only.

---

## Route Daemon

```bash
sudo python3 ta_route_daemon.py --verbose
```

Uses `traceroute -T -p 443` (TCP SYN on HTTPS port) which works through carrier NAT and mobile hotspots where ICMP is blocked. Enriches each hop with MaxMind GeoLite2 city name, country, ISO code, latitude/longitude (stored as integer × 10⁶), ASN number, and organization name. Private and loopback IPs are skipped automatically.

---

## Build System

```bash
# Full rebuild (done automatically by start_kta.sh)
cd kernel_module && make clean && make -j$(nproc)
cd ../gui/build  && cmake .. && make -j$(nproc)
```

CMake dependencies: `Qt6::Core`, `Qt6::Gui`, `Qt6::Widgets`, `Qt6::PrintSupport`, `Qt6::Network`, `SQLite::SQLite3`.

---

## Theme

The entire UI uses a single dark theme defined in `Style.h`:

```
#060b10  main window background
#0d1117  base surface
#131920  panel / input background
#1a2130  card background
#163050  selected row
#5aabff  accent / links / IPs
#20d060  success / ESTABLISHED
#f0b800  warning / SYN states
#f04040  danger / anomalies
#1d6ef5  accent blue
Font: Ubuntu Mono throughout
```

---

## Known Constraints

- Route map hops show `0.0.0.0` on mobile hotspots when ICMP is blocked — resolved by switching to TCP traceroute (`-T -p 443`)
- `traceroute` itself triggers SYN_FLOOD anomaly detection — whitelisted in `detect_anomalies()` via `is_system_process()`
- `SparklineDelegate` must not have `Q_OBJECT` — causes vtable linker error
- All kernel allocations in softirq use `GFP_ATOMIC`; slow operations (`d_path`, task scan) use the `ta_resolver` workqueue
- `get_mm_exe_file()` removed in kernel 6.7 — uses `rcu_dereference(mm->exe_file)` instead
- Stack frames kept under 1024 bytes throughout kernel code
- `spin_lock_bh()` used (not `spin_lock()`) in all softirq contexts

---

## Export

From the **File** menu:

- **JSON Report** — full snapshot of connections, processes, anomalies, DNS, and cost summary
- **CSV** — current connections table as CSV
- **PDF Report** — multi-page report with top processes, anomaly log, countries, DNS summary, and cost breakdown (via `Qt6::PrintSupport`, no external libraries)

---

## Author

Anil Reddy — Bhopal, Madhya Pradesh, India