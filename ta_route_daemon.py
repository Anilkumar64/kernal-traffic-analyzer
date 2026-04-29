#!/usr/bin/env python3
"""Poll KTA route requests, run TCP traceroute, and write hop data to /proc."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

PROC_PENDING = Path("/proc/traffic_analyzer_routes_pending")
PROC_ROUTES = Path("/proc/traffic_analyzer_routes")

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    geoip2 = None  # type: ignore[assignment]


@dataclass(frozen=True)
class PendingRoute:
    ip: str
    domain: str


@dataclass(frozen=True)
class Hop:
    number: int
    ip: str
    rtt_us: int
    host: str = "-"
    city: str = "-"
    country: str = "-"
    country_code: str = "-"
    lat_e6: int = 0
    lon_e6: int = 0
    asn: str = "-"
    org: str = "-"


class GeoIp:
    def __init__(self, city_db: Path | None, asn_db: Path | None) -> None:
        self.city = self._open(city_db)
        self.asn = self._open(asn_db)

    @staticmethod
    def _open(path: Path | None):
        if geoip2 is None or path is None or not path.exists():
            return None
        return geoip2.database.Reader(str(path))

    def enrich(self, hop: Hop) -> Hop:
        if hop.ip == "*" or not self.city and not self.asn:
            return hop

        city = country = country_code = asn = org = "-"
        lat_e6 = lon_e6 = 0
        if self.city:
            try:
                rec = self.city.city(hop.ip)
                city = clean_field(rec.city.name or "-")
                country = clean_field(rec.country.name or "-")
                country_code = clean_field(rec.country.iso_code or "-")
                if rec.location.latitude is not None:
                    lat_e6 = int(rec.location.latitude * 1_000_000)
                if rec.location.longitude is not None:
                    lon_e6 = int(rec.location.longitude * 1_000_000)
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass
        if self.asn:
            try:
                rec = self.asn.asn(hop.ip)
                asn = f"AS{rec.autonomous_system_number}"
                org = clean_field(rec.autonomous_system_organization or "-")
            except (geoip2.errors.AddressNotFoundError, ValueError):
                pass

        return Hop(hop.number, hop.ip, hop.rtt_us, hop.host, city, country,
                   country_code, lat_e6, lon_e6, asn, org)

def clean_field(value: str) -> str:
    return value.strip().replace(" ", "_").replace("\t", "_") or "-"

def is_routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_global)

def read_pending(path: Path = PROC_PENDING) -> list[PendingRoute]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logging.debug("cannot read %s: %s", path, exc)
        return []

    routes: list[PendingRoute] = []
    for line in lines:
        parts = line.split(maxsplit=1)
        if not parts or not is_routable(parts[0]):
            continue
        routes.append(PendingRoute(parts[0], parts[1] if len(parts) > 1 else "-"))
    return routes

def run_traceroute(ip: str) -> str | None:
    cmd = ["traceroute", "-T", "-p", "443", "-n", "-q", "1", "-w", "2", "-m", "32", ip]
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=70)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logging.debug("traceroute failed for %s: %s", ip, exc)
        return None
    if result.returncode not in (0, 1):
        logging.debug("traceroute returned %s for %s: %s", result.returncode, ip, result.stderr)
        return None
    return result.stdout

def parse_hops(output: str) -> list[Hop]:
    hops: list[Hop] = []
    line_re = re.compile(r"^\s*(\d+)\s+(.+)$")
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    rtt_re = re.compile(r"(\d+(?:\.\d+)?)\s*ms")

    for line in output.splitlines()[1:]:
        match = line_re.match(line)
        if not match:
            continue
        number = int(match.group(1))
        rest = match.group(2)
        if "*" in rest and not ip_re.search(rest):
            hops.append(Hop(number, "*", 0))
            continue
        ip_match = ip_re.search(rest)
        rtt_match = rtt_re.search(rest)
        if not ip_match:
            continue
        rtt_us = int(float(rtt_match.group(1)) * 1000) if rtt_match else 0
        ip = ip_match.group(1)
        hops.append(Hop(number, ip, rtt_us, ip))
    return hops

def route_payload(route: PendingRoute, hops: Iterable[Hop], status: str) -> str:
    lines = [f"DEST {route.ip}"]
    for hop in hops:
        lines.append(
            "HOP "
            f"{hop.number} {hop.ip} {hop.rtt_us} {clean_field(hop.host)} "
            f"{hop.city} {hop.country} {hop.country_code} {hop.lat_e6} {hop.lon_e6} "
            f"{hop.asn} {hop.org}"
        )
    lines.append(f"STATUS {status}")
    return "\n".join(lines) + "\n"

def write_route(payload: str, path: Path = PROC_ROUTES) -> None:
    try:
        path.write_text(payload, encoding="utf-8")
    except OSError as exc:
        logging.debug("cannot write %s: %s", path, exc)

def trace_route(route: PendingRoute, geo: GeoIp) -> None:
    output = run_traceroute(route.ip)
    if output is None:
        return
    hops = [geo.enrich(hop) for hop in parse_hops(output)]
    write_route(route_payload(route, hops, "DONE" if hops else "FAILED"))

def main() -> int:
    parser = argparse.ArgumentParser(description="Kernel Traffic Analyzer route daemon")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--city-db", type=Path)
    parser.add_argument("--asn-db", type=Path)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    geo = GeoIp(args.city_db, args.asn_db)

    while True:
        for route in read_pending():
            trace_route(route, geo)
        time.sleep(args.poll_interval)


if __name__ == "__main__":
    raise SystemExit(main())
