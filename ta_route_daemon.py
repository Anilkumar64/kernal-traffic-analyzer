#!/usr/bin/env python3
"""
ta_route_daemon.py — Kernel Traffic Analyzer Route Daemon
Phase 5 userspace: bridges kernel ↔ traceroute ↔ MaxMind GeoIP

Polls /proc/traffic_analyzer_routes_pending every 2 seconds.
For each pending IP:
  1. Runs traceroute
  2. Enriches each hop with MaxMind GeoLite2 (city + ASN)
  3. Writes results back to /proc/traffic_analyzer_routes

Requirements:
    pip install geoip2
    /usr/share/GeoIP/GeoLite2-City.mmdb  (free from maxmind.com)
    /usr/share/GeoIP/GeoLite2-ASN.mmdb   (free from maxmind.com)

Usage:
    sudo python3 ta_route_daemon.py
    sudo python3 ta_route_daemon.py --interval 3 --timeout 1
"""

import subprocess
import re
import time
import sys
import os
import argparse
import logging
import socket
import ipaddress

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("[WARN] geoip2 not installed. Run: pip install geoip2", file=sys.stderr)
    print("[WARN] Continuing without GeoIP enrichment.", file=sys.stderr)

# ============================================================
# Config
# ============================================================
PENDING_FILE     = "/proc/traffic_analyzer_routes_pending"
ROUTES_FILE      = "/proc/traffic_analyzer_routes"
CITY_DB          = "/usr/share/GeoIP/GeoLite2-City.mmdb"
ASN_DB           = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
DEFAULT_INTERVAL = 2      # seconds between polls
DEFAULT_TIMEOUT  = 1      # traceroute per-hop timeout
DEFAULT_QUERIES  = 1      # traceroute queries per hop
DEFAULT_MAXHOPS  = 20     # traceroute max TTL

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ta_route_daemon")

# ============================================================
# GeoIP
# ============================================================
class GeoIP:
    def __init__(self):
        self.city_reader = None
        self.asn_reader  = None

        if not GEOIP_AVAILABLE:
            return

        if os.path.exists(CITY_DB):
            try:
                self.city_reader = geoip2.database.Reader(CITY_DB)
                log.info(f"Loaded city DB: {CITY_DB}")
            except Exception as e:
                log.warning(f"Could not open city DB: {e}")
        else:
            log.warning(f"City DB not found: {CITY_DB}")
            log.warning("Download from: https://www.maxmind.com/en/geolite2/signup")

        if os.path.exists(ASN_DB):
            try:
                self.asn_reader = geoip2.database.Reader(ASN_DB)
                log.info(f"Loaded ASN DB: {ASN_DB}")
            except Exception as e:
                log.warning(f"Could not open ASN DB: {e}")
        else:
            log.warning(f"ASN DB not found: {ASN_DB}")

    def lookup(self, ip: str) -> dict:
        """Returns dict with city, country, cc, lat_e6, lon_e6, asn, org."""
        result = {
            "city":    "-",
            "country": "-",
            "cc":      "-",
            "lat_e6":  0,
            "lon_e6":  0,
            "asn":     0,
            "org":     "-",
        }

        if not ip or ip == "*":
            return result

        # Try city DB
        if self.city_reader:
            try:
                r = self.city_reader.city(ip)
                result["city"]    = r.city.name or "-"
                result["country"] = r.country.name or "-"
                result["cc"]      = r.country.iso_code or "-"
                if r.location.latitude is not None:
                    result["lat_e6"] = int(r.location.latitude  * 1_000_000)
                if r.location.longitude is not None:
                    result["lon_e6"] = int(r.location.longitude * 1_000_000)
            except (geoip2.errors.AddressNotFoundError, Exception):
                pass

        # Try ASN DB
        if self.asn_reader:
            try:
                r = self.asn_reader.asn(ip)
                result["asn"] = r.autonomous_system_number or 0
                result["org"] = r.autonomous_system_organization or "-"
            except (geoip2.errors.AddressNotFoundError, Exception):
                pass

        return result

    def close(self):
        if self.city_reader: self.city_reader.close()
        if self.asn_reader:  self.asn_reader.close()

# ============================================================
# Traceroute
# ============================================================
# Matches lines like:
#  1  192.168.1.1  1.234 ms
#  2  * * *
#  3  10.0.0.1 (10.0.0.1)  12.500 ms
HOP_RE = re.compile(
    r"^\s*(\d+)\s+"             # hop number
    r"([\w\.\:\-]+|\*)"        # hostname or *
    r"(?:\s+\(([^\)]+)\))?"    # optional (ip)
    r"(?:\s+([\d\.]+)\s*ms)?"  # optional rtt
)

def run_traceroute(dest_ip: str, timeout: int, queries: int, maxhops: int) -> list:
    """
    Runs traceroute and returns list of hop dicts:
    {hop_n, hop_ip, host, rtt_ms}
    """
    cmd = [
        "traceroute",
        "-n",                      # numeric, no DNS reverse lookups
        "-q", str(queries),        # queries per hop
        "-w", str(timeout),        # per-hop timeout
        "-m", str(maxhops),        # max hops
        dest_ip
    ]

    hops = []
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=maxhops * timeout * queries + 5
        )
        for line in result.stdout.splitlines():
            m = HOP_RE.match(line)
            if not m:
                continue

            hop_n    = int(m.group(1))
            host     = m.group(2)
            hop_ip   = m.group(3) or host   # prefer explicit IP in parens
            rtt_str  = m.group(4)
            rtt_ms   = float(rtt_str) if rtt_str else 0.0

            # Sanitize: if host is *, skip
            if host == "*":
                hop_ip = "*"

            # Validate IP
            try:
                ipaddress.ip_address(hop_ip)
            except ValueError:
                hop_ip = "*"

            hops.append({
                "hop_n":  hop_n,
                "hop_ip": hop_ip,
                "host":   host if host != "*" else "-",
                "rtt_ms": rtt_ms,
            })

    except subprocess.TimeoutExpired:
        log.warning(f"traceroute timed out for {dest_ip}")
    except FileNotFoundError:
        log.error("traceroute not found. Install: sudo apt install traceroute")
    except Exception as e:
        log.error(f"traceroute error for {dest_ip}: {e}")

    return hops

# ============================================================
# Write to kernel
# ============================================================
def write_to_kernel(dest_ip: str, domain: str, hops: list):
    """
    Writes the DEST/STATUS/HOP protocol to /proc/traffic_analyzer_routes.
    Format expected by kernel:
        DEST <ip>
        STATUS DONE
        HOP <n> <ip> <rtt_us> <host> <city> <country> <cc> <lat_e6> <lon_e6> <asn> <org>
    """
    lines = []
    lines.append(f"DEST {dest_ip}")

    if not hops:
        lines.append("STATUS FAILED")
    else:
        lines.append("STATUS DONE")
        for h in hops:
            geo = h.get("geo", {})
            rtt_us = int(h["rtt_ms"] * 1000)  # ms → µs
            line = (
                f"HOP {h['hop_n']} "
                f"{h['hop_ip']} "
                f"{rtt_us} "
                f"{h['host']} "
                f"{geo.get('city',    '-')} "
                f"{geo.get('country', '-')} "
                f"{geo.get('cc',      '-')} "
                f"{geo.get('lat_e6',   0)} "
                f"{geo.get('lon_e6',   0)} "
                f"{geo.get('asn',      0)} "
                f"{geo.get('org',     '-')}"
            )
            lines.append(line)

    payload = "\n".join(lines) + "\n"

    try:
        with open(ROUTES_FILE, "w") as f:
            f.write(payload)
        log.info(f"  Wrote {len(hops)} hops for {dest_ip} ({domain})")
    except PermissionError:
        log.error(f"Permission denied writing to {ROUTES_FILE}. Run as root.")
    except FileNotFoundError:
        log.error(f"{ROUTES_FILE} not found. Is the kernel module loaded?")
    except Exception as e:
        log.error(f"Write error for {dest_ip}: {e}")

# ============================================================
# Read pending IPs
# ============================================================
def read_pending() -> list:
    """Returns list of (ip, domain) tuples."""
    pending = []
    try:
        with open(PENDING_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(None, 1)
                ip     = parts[0]
                domain = parts[1] if len(parts) > 1 else "-"

                # Validate it's an IP
                try:
                    ipaddress.ip_address(ip)
                    pending.append((ip, domain))
                except ValueError:
                    log.warning(f"Skipping invalid IP in pending: {ip!r}")

    except FileNotFoundError:
        pass   # module not loaded or no pending routes
    except Exception as e:
        log.error(f"Error reading pending: {e}")

    return pending

# ============================================================
# Main loop
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="KTA Route Daemon — traceroute + GeoIP bridge for kernel module")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help=f"Poll interval seconds (default {DEFAULT_INTERVAL})")
    parser.add_argument("--timeout",  type=int,   default=DEFAULT_TIMEOUT,
                        help=f"Traceroute per-hop timeout (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--queries",  type=int,   default=DEFAULT_QUERIES,
                        help=f"Traceroute queries per hop (default {DEFAULT_QUERIES})")
    parser.add_argument("--maxhops",  type=int,   default=DEFAULT_MAXHOPS,
                        help=f"Traceroute max hops (default {DEFAULT_MAXHOPS})")
    parser.add_argument("--verbose",  action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    if os.geteuid() != 0:
        log.error("Must run as root (sudo) to write to /proc files and run traceroute")
        sys.exit(1)

    log.info("KTA Route Daemon starting")
    log.info(f"Poll interval: {args.interval}s  |  "
             f"traceroute timeout: {args.timeout}s  |  "
             f"max hops: {args.maxhops}")

    geo = GeoIP()

    in_progress = set()   # IPs currently being traced (avoid re-launching)

    try:
        while True:
            pending = read_pending()

            for ip, domain in pending:
                if ip in in_progress:
                    continue
                in_progress.add(ip)

                log.info(f"Tracing {ip} ({domain})")

                # Run traceroute
                hops = run_traceroute(ip, args.timeout, args.queries, args.maxhops)

                if not hops:
                    log.warning(f"No hops returned for {ip}")
                    write_to_kernel(ip, domain, [])
                    in_progress.discard(ip)
                    continue

                # Enrich each hop with GeoIP
                for hop in hops:
                    if hop["hop_ip"] == "*":
                        hop["geo"] = {
                            "city":"-","country":"-","cc":"-",
                            "lat_e6":0,"lon_e6":0,"asn":0,"org":"-"
                        }
                    else:
                        hop["geo"] = geo.lookup(hop["hop_ip"])

                    if args.verbose:
                        g = hop["geo"]
                        log.debug(
                            f"  hop {hop['hop_n']:2d}  {hop['hop_ip']:16s}  "
                            f"{hop['rtt_ms']:6.1f}ms  "
                            f"{g['city']}, {g['country']}  "
                            f"AS{g['asn']} {g['org']}"
                        )

                write_to_kernel(ip, domain, hops)
                in_progress.discard(ip)

            time.sleep(args.interval)

    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        geo.close()

if __name__ == "__main__":
    main()