#!/usr/bin/env python3
"""
ta_route_daemon.py — TCP Traceroute + GeoIP Route Enrichment Daemon
Kernel Traffic Analyzer (KTA) v6.0

Polls /proc/traffic_analyzer_routes_pending every 2 seconds.
For each pending IP it runs:
    traceroute -T -p 443 -n -q 1 -w 2 <ip>
Enriches each hop with MaxMind GeoLite2 City + ASN data.
Writes results to /proc/traffic_analyzer_routes.

/proc column contract (15 cols per hop, space-separated):
  0=DEST_IP  1=DOMAIN      2=STATUS    3=TOTAL_HOPS  4=HOP_N
  5=HOP_IP   6=HOST        7=RTT_MS    8=CITY         9=COUNTRY
  10=CC      11=LAT_E6     12=LON_E6   13=ASN         14=ORG

LAT_E6 / LON_E6 = degrees × 1_000_000  (integer, no decimal point)
"""

import argparse
import ipaddress
import logging
import os
import re
import signal
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from pathlib import Path
from typing import Optional

# Kernel proc write protocol:
# DEST <ip>
# HOP <n> <hop_ip> <rtt_us> <host> <city> <country> <cc> <lat_e6> <lon_e6> <asn> <org>
# STATUS <DONE|FAILED|RUNNING>

# ── GeoIP2 ────────────────────────────────────────────────────────────────────
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("[WARN] geoip2 not installed — run: pip install geoip2 --break-system-packages",
          file=sys.stderr)

# ── /proc paths ───────────────────────────────────────────────────────────────
PROC_PENDING = "/proc/traffic_analyzer_routes_pending"
PROC_ROUTES  = "/proc/traffic_analyzer_routes"

# ── MaxMind DB paths ──────────────────────────────────────────────────────────
GEOIP_CITY_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
GEOIP_ASN_DB  = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

# ── Tunables ──────────────────────────────────────────────────────────────────
POLL_INTERVAL_S   = 2       # seconds between pending-queue checks
TRACEROUTE_HOPS   = 20      # -m (max hops)
TRACEROUTE_QUERIES= 1       # -q (queries per hop) — keep fast
TRACEROUTE_WAIT_S = 2       # -w (probe timeout seconds)
TRACEROUTE_PORT   = 443     # -p (TCP SYN port, works through NAT)
MAX_CONCURRENT    = 8       # never trace more than this many IPs at once
RETRY_LIMIT       = 2       # retry failed traces this many times
COMPLETED_TTL_S   = 120     # forget a completed IP after this many seconds
FIELD_SEP         = " "     # column separator written to /proc
UNKNOWN           = "?"     # placeholder for unknown fields

# ── Logging ───────────────────────────────────────────────────────────────────
log = logging.getLogger("kta.route_daemon")

# ──────────────────────────────────────────────────────────────────────────────
# IP helpers
# ──────────────────────────────────────────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.64.0.0/10"),   # carrier-grade NAT
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
]


def is_routable(ip_str: str) -> bool:
    """Return True only if the IP is a globally routable unicast address."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return False
    for net in _PRIVATE_NETWORKS:
        try:
            if addr in net:
                return False
        except TypeError:
            pass
    return True


def sanitise(value: str) -> str:
    """Strip whitespace and replace spaces/tabs inside a field with '_'."""
    return value.strip().replace(" ", "_").replace("\t", "_") or UNKNOWN


# ──────────────────────────────────────────────────────────────────────────────
# GeoIP wrapper
# ──────────────────────────────────────────────────────────────────────────────

class GeoIPReader:
    """Thin wrapper around two MaxMind readers; handles missing DB gracefully."""

    def __init__(self, city_path: str, asn_path: str) -> None:
        self._city: Optional["geoip2.database.Reader"] = None
        self._asn:  Optional["geoip2.database.Reader"] = None

        if not GEOIP_AVAILABLE:
            log.warning("geoip2 module not available — geo enrichment disabled")
            return

        for attr, path, label in (
            ("_city", city_path, "City"),
            ("_asn",  asn_path,  "ASN"),
        ):
            if Path(path).exists():
                try:
                    setattr(self, attr, geoip2.database.Reader(path))
                    log.info("Loaded GeoLite2-%s from %s", label, path)
                except Exception as exc:
                    log.warning("Cannot open %s: %s", path, exc)
            else:
                log.warning("GeoLite2-%s not found at %s", label, path)

    def lookup(self, ip_str: str) -> dict:
        """Return a dict with city, country, cc, lat_e6, lon_e6, asn, org."""
        result = {
            "city":    UNKNOWN,
            "country": UNKNOWN,
            "cc":      UNKNOWN,
            "lat_e6":  0,
            "lon_e6":  0,
            "asn":     0,
            "org":     UNKNOWN,
        }

        if not is_routable(ip_str):
            result["city"] = "Private"
            return result

        # City / country / coords
        if self._city:
            try:
                rec = self._city.city(ip_str)
                if rec.city.name:
                    result["city"] = sanitise(rec.city.name)
                if rec.country.name:
                    result["country"] = sanitise(rec.country.name)
                if rec.country.iso_code:
                    result["cc"] = rec.country.iso_code
                if rec.location.latitude is not None:
                    result["lat_e6"] = int(rec.location.latitude  * 1_000_000)
                    result["lon_e6"] = int(rec.location.longitude * 1_000_000)
            except (geoip2.errors.AddressNotFoundError, Exception):
                pass

        # ASN / org
        if self._asn:
            try:
                rec = self._asn.asn(ip_str)
                result["asn"] = rec.autonomous_system_number or 0
                if rec.autonomous_system_organization:
                    result["org"] = sanitise(rec.autonomous_system_organization)
            except (geoip2.errors.AddressNotFoundError, Exception):
                pass

        return result

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass


# ──────────────────────────────────────────────────────────────────────────────
# Traceroute parser
# ──────────────────────────────────────────────────────────────────────────────

# Matches lines like:
#  " 3  203.0.113.1  12.345 ms"
#  " 5  * * *"
_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"           # hop number
    r"([\d.]+|\*)"            # IP or '*'
    r"(?:\s+([\d.]+)\s*ms)?"  # optional RTT
)


def run_traceroute(dest_ip: str, verbose: bool = False) -> list[dict]:
    """
    Execute traceroute and return a list of hop dicts:
        { hop_n, hop_ip, rtt_ms }
    Hops with no response are represented with hop_ip="*" rtt_ms=0.
    """
    cmd = [
        "traceroute",
        "-T",                          # TCP SYN (works through NAT/mobile hotspot)
        f"-p{TRACEROUTE_PORT}",        # destination port
        f"-m{TRACEROUTE_HOPS}",        # max hops
        f"-q{TRACEROUTE_QUERIES}",     # probes per hop
        f"-w{TRACEROUTE_WAIT_S}",      # wait per probe
        "-n",                          # no reverse DNS (we do our own mapping)
        dest_ip,
    ]

    if verbose:
        log.debug("Running: %s", " ".join(cmd))

    hops: list[dict] = []
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TRACEROUTE_HOPS * (TRACEROUTE_WAIT_S + 1) + 5,
        )
        output = proc.stdout
        if verbose and proc.stderr:
            log.debug("traceroute stderr: %s", proc.stderr.strip())
    except subprocess.TimeoutExpired:
        log.warning("traceroute timed out for %s", dest_ip)
        return hops
    except FileNotFoundError:
        log.error("traceroute binary not found — install: sudo apt install traceroute")
        return hops
    except Exception as exc:
        log.error("traceroute failed for %s: %s", dest_ip, exc)
        return hops

    for line in output.splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        hop_n  = int(m.group(1))
        hop_ip = m.group(2)           # may be "*"
        rtt_s  = m.group(3)
        rtt_ms = float(rtt_s) if rtt_s else 0.0
        hops.append({"hop_n": hop_n, "hop_ip": hop_ip, "rtt_ms": rtt_ms})

    return hops


# ──────────────────────────────────────────────────────────────────────────────
# /proc interface
# ──────────────────────────────────────────────────────────────────────────────

def read_pending() -> list[tuple[str, str]]:
    """
    Read /proc/traffic_analyzer_routes_pending.
    Each line: <dest_ip> <domain>
    Returns list of (dest_ip, domain) tuples.
    """
    entries: list[tuple[str, str]] = []
    try:
        with open(PROC_PENDING, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    entries.append((parts[0], parts[1]))
                elif len(parts) == 1:
                    entries.append((parts[0], UNKNOWN))
    except FileNotFoundError:
        log.error("%s not found — is the kernel module loaded?", PROC_PENDING)
    except PermissionError:
        log.error("Permission denied reading %s — run as root", PROC_PENDING)
    except Exception as exc:
        log.error("Error reading pending queue: %s", exc)
    return entries


def write_route(dest_ip: str, domain: str, hops: list[dict],
                geo: GeoIPReader, status: str = "OK") -> None:
    """
    Write one route (all its hops) to /proc/traffic_analyzer_routes.

    Each hop line is exactly 15 space-separated columns:
      DEST_IP DOMAIN STATUS TOTAL_HOPS HOP_N
      HOP_IP  HOST   RTT_MS CITY       COUNTRY
      CC      LAT_E6 LON_E6 ASN        ORG
    """
    total_hops = len(hops)
    lines: list[str] = [f"DEST {sanitise(dest_ip)}"]

    if total_hops == 0:
        lines.append("STATUS FAILED")
        try:
            with open(PROC_ROUTES, "w") as fh:
                fh.write("\n".join(lines) + "\n")
        except Exception as exc:
            log.error("Failed to write route for %s: %s", dest_ip, exc)
        return

    for hop in hops:
        hop_ip  = hop["hop_ip"]
        rtt_ms  = hop["rtt_ms"]
        hop_n   = hop["hop_n"]

        if hop_ip == "*" or not is_routable(hop_ip):
            # Non-responsive or private hop — zero out geo fields
            geo_data = {
                "city":    UNKNOWN,
                "country": UNKNOWN,
                "cc":      UNKNOWN,
                "lat_e6":  0,
                "lon_e6":  0,
                "asn":     0,
                "org":     UNKNOWN,
            }
        else:
            geo_data = geo.lookup(hop_ip)

        cols = [
            "HOP",
            str(hop_n),
            hop_ip if hop_ip != "*" else UNKNOWN,
            UNKNOWN,                        # HOST — kernel does reverse DNS itself
            str(int(rtt_ms * 1000)),
            geo_data["city"],
            geo_data["country"],
            geo_data["cc"],
            str(geo_data["lat_e6"]),
            str(geo_data["lon_e6"]),
            str(geo_data["asn"]),
            geo_data["org"],
        ]
        lines.append(FIELD_SEP.join(cols))

    lines.append("STATUS DONE" if status == "OK" else "STATUS FAILED")

    try:
        with open(PROC_ROUTES, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        log.debug("Wrote %d hop(s) for %s", total_hops, dest_ip)
    except Exception as exc:
        log.error("Failed to write route for %s: %s", dest_ip, exc)


# ──────────────────────────────────────────────────────────────────────────────
# Main daemon loop
# ──────────────────────────────────────────────────────────────────────────────

class RouteDaemon:
    def __init__(self, verbose: bool = False) -> None:
        self.verbose    = verbose
        self.geo        = GeoIPReader(GEOIP_CITY_DB, GEOIP_ASN_DB)
        self._running   = True
        self._in_flight: set[str] = set()    # IPs currently being traced
        # completed cache: ip -> expiry timestamp  (avoid re-tracing)
        self._completed: dict[str, float] = {}
        # retry counter: ip -> attempt count
        self._retries:   dict[str, int]   = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT)
        self._futures = {}

        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame) -> None:
        log.info("Signal %d received — shutting down", signum)
        self._running = False

    def _is_completed(self, ip: str) -> bool:
        exp = self._completed.get(ip)
        if exp is None:
            return False
        if time.monotonic() > exp:
            del self._completed[ip]
            return False
        return True

    def _mark_completed(self, ip: str) -> None:
        self._completed[ip] = time.monotonic() + COMPLETED_TTL_S

    def _expire_completed_cache(self) -> None:
        now = time.monotonic()
        expired = [ip for ip, exp in self._completed.items() if now > exp]
        for ip in expired:
            del self._completed[ip]

    def process_ip(self, dest_ip: str, domain: str) -> tuple[str, str, list[dict], int]:
        """Trace one IP and return the result for the main thread to commit."""
        log.info("Tracing %s (%s) …", dest_ip, domain)

        attempt = self._retries.get(dest_ip, 0) + 1
        self._retries[dest_ip] = attempt

        hops = run_traceroute(dest_ip, verbose=self.verbose)
        return dest_ip, domain, hops, attempt

    def _complete_future(self, future) -> None:
        dest_ip = None
        try:
            dest_ip, domain, hops, attempt = future.result()
        except Exception as exc:
            log.error("Route worker failed: %s", exc)
            return
        finally:
            with self._lock:
                for ip, fut in list(self._futures.items()):
                    if fut is future:
                        dest_ip = ip
                        del self._futures[ip]
                        self._in_flight.discard(ip)
                        break

        if dest_ip is None:
            return

        if hops:
            write_route(dest_ip, domain, hops, self.geo, status="OK")
            self._mark_completed(dest_ip)
            self._retries.pop(dest_ip, None)
            log.info("Route for %s: %d hop(s)", dest_ip, len(hops))
        else:
            if attempt >= RETRY_LIMIT:
                log.warning("No route for %s after %d attempt(s)", dest_ip, attempt)
                write_route(dest_ip, domain, [], self.geo, status="FAIL")
                self._mark_completed(dest_ip)
                self._retries.pop(dest_ip, None)
            else:
                log.debug("No hops for %s — will retry (attempt %d/%d)",
                          dest_ip, attempt, RETRY_LIMIT)

    def run(self) -> None:
        log.info("KTA route daemon started (PID %d)", os.getpid())
        log.info("Polling %s every %ds", PROC_PENDING, POLL_INTERVAL_S)

        while self._running:
            self._expire_completed_cache()

            with self._lock:
                futures = list(self._futures.values())
            try:
                for future in as_completed(futures, timeout=0.05):
                    self._complete_future(future)
            except TimeoutError:
                pass

            pending = read_pending()
            for dest_ip, domain in pending:
                if not dest_ip or dest_ip == UNKNOWN:
                    continue
                if not is_routable(dest_ip):
                    log.debug("Skipping non-routable %s", dest_ip)
                    continue
                if self._is_completed(dest_ip):
                    log.debug("Already traced %s (cached)", dest_ip)
                    continue
                with self._lock:
                    if dest_ip in self._in_flight:
                        log.debug("Already in-flight: %s", dest_ip)
                        continue
                    if len(self._in_flight) >= MAX_CONCURRENT:
                        log.debug("Concurrency limit reached (%d) — deferring %s",
                                  MAX_CONCURRENT, dest_ip)
                        break
                    self._in_flight.add(dest_ip)
                    self._futures[dest_ip] = self._executor.submit(
                        self.process_ip, dest_ip, domain)

            time.sleep(POLL_INTERVAL_S)

        self._executor.shutdown(wait=True)
        with self._lock:
            remaining = list(self._futures.values())
        for future in as_completed(remaining):
            self._complete_future(future)
        log.info("Route daemon stopped")
        self.geo.close()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def _check_prerequisites() -> bool:
    ok = True

    # Must be root to write /proc kernel files
    if os.geteuid() != 0:
        log.error("Must run as root (sudo)")
        ok = False

    # /proc files must exist — module must be loaded
    for path in (PROC_PENDING, PROC_ROUTES):
        if not Path(path).exists():
            log.error("%s not found — load the kernel module first:", path)
            log.error("  sudo insmod traffic_analyzer.ko")
            ok = False

    # traceroute binary
    result = subprocess.run(["which", "traceroute"], capture_output=True, text=True)
    if result.returncode != 0:
        log.error("traceroute not found — install: sudo apt install traceroute")
        ok = False

    # geoip2 Python package
    if not GEOIP_AVAILABLE:
        log.warning("geoip2 not available — geo fields will be '?' (non-fatal)")

    return ok


def main() -> None:
    # Declare globals before any reference to them in this function scope
    global POLL_INTERVAL_S, GEOIP_CITY_DB, GEOIP_ASN_DB

    parser = argparse.ArgumentParser(
        description="KTA v6.0 — TCP traceroute + GeoIP route enrichment daemon"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=POLL_INTERVAL_S,
        metavar="SECONDS",
        help=f"Pending queue poll interval (default: {POLL_INTERVAL_S}s)",
    )
    parser.add_argument(
        "--city-db",
        default=GEOIP_CITY_DB,
        metavar="PATH",
        help=f"Path to GeoLite2-City.mmdb (default: {GEOIP_CITY_DB})",
    )
    parser.add_argument(
        "--asn-db",
        default=GEOIP_ASN_DB,
        metavar="PATH",
        help=f"Path to GeoLite2-ASN.mmdb (default: {GEOIP_ASN_DB})",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Apply CLI overrides to module-level config
    POLL_INTERVAL_S = args.poll_interval
    GEOIP_CITY_DB   = args.city_db
    GEOIP_ASN_DB    = args.asn_db

    if not _check_prerequisites():
        sys.exit(1)

    daemon = RouteDaemon(verbose=args.verbose)
    daemon.run()


if __name__ == "__main__":
    main()
