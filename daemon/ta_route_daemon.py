#!/usr/bin/env python3
"""
Kernel Traffic Analyzer - Route Daemon.

Polls /proc/traffic_analyzer_routes_pending, runs traceroute for each IP,
optionally enriches hops with GeoIP2, writes results to
/proc/traffic_analyzer_routes.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


class GeoEnricher:
    """Loads optional GeoIP2 databases and enriches hop IP addresses."""

    def __init__(self) -> None:
        """Initialize GeoIP readers when geoip2 and databases are available."""
        self.city_reader = None
        self.asn_reader = None
        try:
            import geoip2.database  # type: ignore

            city_paths = [
                Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
                Path("/usr/share/GeoIP/GeoIP2-City.mmdb"),
            ]
            asn_paths = [
                Path("/usr/share/GeoIP/GeoLite2-ASN.mmdb"),
                Path("/usr/share/GeoIP/GeoIP2-ASN.mmdb"),
            ]
            for path in city_paths:
                if path.exists():
                    self.city_reader = geoip2.database.Reader(str(path))
                    break
            for path in asn_paths:
                if path.exists():
                    self.asn_reader = geoip2.database.Reader(str(path))
                    break
        except Exception as exc:  # noqa: BLE001 - optional enrichment must not stop tracing.
            logging.getLogger(__name__).info("GeoIP disabled: %s", exc)

    def enrich(self, ip_str: str) -> dict[str, Any]:
        """Return country, coordinates, ASN, and organization for an IP."""
        if ip_str == "*":
            return {}

        result: dict[str, Any] = {}
        if self.city_reader is not None:
            try:
                city = self.city_reader.city(ip_str)
                result["country"] = city.country.iso_code or ""
                result["lat"] = city.location.latitude if city.location.latitude is not None else ""
                result["lon"] = city.location.longitude if city.location.longitude is not None else ""
            except Exception:  # noqa: BLE001 - missing GeoIP records are expected.
                pass

        if self.asn_reader is not None:
            try:
                asn = self.asn_reader.asn(ip_str)
                result["asn"] = asn.autonomous_system_number or ""
                result["org"] = asn.autonomous_system_organization or ""
            except Exception:  # noqa: BLE001 - missing GeoIP records are expected.
                pass

        return result


class RouteTracer:
    """Runs traceroute and parses hop lines into dictionaries."""

    def __init__(self, enricher: GeoEnricher) -> None:
        """Store the GeoIP enricher used for parsed hop addresses."""
        self.enricher = enricher

    def trace(self, ip_str: str) -> list[dict[str, Any]]:
        """Trace a target IP and return ordered hop dictionaries."""
        try:
            proc = subprocess.run(
                ["traceroute", "-T", "-n", "-q1", "-w1", ip_str],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return []

        hops: list[dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            match = re.match(r"^\s*(\d+)\s+([\d.]+)\s+([\d.]+)\s+ms", line)
            if match:
                hop_ip = match.group(2)
                hop: dict[str, Any] = {
                    "hop": int(match.group(1)),
                    "ip": hop_ip,
                    "rtt_ms": float(match.group(3)),
                }
                hop.update(self.enricher.enrich(hop_ip))
                hops.append(hop)
                continue

            timeout_match = re.match(r"^\s*(\d+)\s+\*\s+\*\s+\*", line)
            if timeout_match:
                hops.append({"hop": int(timeout_match.group(1)), "ip": "*", "rtt_ms": 0.0})

        return hops


class ProcWriter:
    """Reads pending route requests and writes completed route hops to procfs."""

    PROC_ROUTES = "/proc/traffic_analyzer_routes"
    PROC_PENDING = "/proc/traffic_analyzer_routes_pending"
    LOG_PATH = "/var/log/kta_route_daemon.log"

    def read_pending(self) -> list[str]:
        """Read pending target IPs from procfs, returning an empty list if absent."""
        try:
            with open(self.PROC_PENDING, "r", encoding="utf-8") as pending:
                return [line.strip() for line in pending if line.strip()]
        except FileNotFoundError:
            return []
        except OSError as exc:
            logging.getLogger(__name__).warning("Failed reading pending routes: %s", exc)
            return []

    def write_result(self, target_ip: str, hops: list[dict[str, Any]]) -> None:
        """Write traceroute hop results to the kernel route proc file."""
        lines = []
        for hop in hops:
            lines.append(
                f"{target_ip}|{hop['hop']}|{hop['ip']}|{hop['rtt_ms']:.1f}|"
                f"{hop.get('country', '')}|{hop.get('lat', '')}|{hop.get('lon', '')}|"
                f"{hop.get('asn', '')}|{hop.get('org', '')}\n"
            )

        try:
            with open(self.PROC_ROUTES, "w", encoding="utf-8") as routes:
                routes.writelines(lines)
        except OSError as exc:
            logging.getLogger(__name__).warning("Failed writing routes for %s: %s", target_ip, exc)


class RouteDaemon:
    """Coordinates polling, tracing, enrichment, and procfs writes."""

    def __init__(self) -> None:
        """Configure logging and initialize daemon collaborators."""
        self._setup_logging()
        self.log = logging.getLogger(__name__)
        self.enricher = GeoEnricher()
        self.tracer = RouteTracer(self.enricher)
        self.writer = ProcWriter()
        self.traced_ips: set[str] = set()
        self.running = True

    def _setup_logging(self) -> None:
        """Install file and stream logging handlers."""
        handlers: list[logging.Handler] = [logging.StreamHandler()]
        try:
            handlers.append(logging.FileHandler(ProcWriter.LOG_PATH))
        except OSError:
            pass
        logging.basicConfig(
            handlers=handlers,
            format="%(asctime)s [%(levelname)s] %(message)s",
            level=logging.INFO,
        )

    def stop(self) -> None:
        """Request a clean daemon shutdown."""
        self.running = False

    def run(self) -> None:
        """Poll pending route targets and trace new IPs until stopped."""
        while self.running:
            pending = self.writer.read_pending()
            for ip in pending:
                if ip not in self.traced_ips:
                    self.log.info("Tracing %s", ip)
                    hops = self.tracer.trace(ip)
                    self.writer.write_result(ip, hops)
                    self.traced_ips.add(ip)
                    self.log.info("Wrote %d hops for %s", len(hops), ip)
            time.sleep(2)


if __name__ == "__main__":
    daemon = RouteDaemon()
    try:
        daemon.run()
    except KeyboardInterrupt:
        daemon.stop()
        sys.exit(0)
