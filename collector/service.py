"""Standalone Windows DNS collector service."""

import argparse
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from scapy.sendrecv import sniff

from collector.dns_parser import packet_to_event
from processing.correlator import DnsCorrelator
from storage.database import initialize_database, insert_event

LOGGER = logging.getLogger(__name__)


@dataclass
class CollectorHealth:
    """Runtime status and counters exposed by the collector."""

    status: str = "created"
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    last_event_at: datetime | None = None
    packets_seen: int = 0
    events_persisted: int = 0
    malformed_packets: int = 0
    error: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "status": self.status,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "last_event_at": self.last_event_at,
                "packets_seen": self.packets_seen,
                "events_persisted": self.events_persisted,
                "malformed_packets": self.malformed_packets,
                "error": self.error,
            }


class DnsCollector:
    """Capture DNS traffic on one configured Npcap interface."""

    def __init__(self, interface: str, packet_filter: str, database_path: str | Path,
                 health_path: str | Path = "outputs/collector_health.json",
                 stop_path: str | Path = "outputs/collector.stop"):
        if not interface:
            raise ValueError("A Windows Npcap capture interface is required")
        self.interface = interface
        self.packet_filter = packet_filter
        self.database_path = Path(database_path)
        self.health_path = Path(health_path)
        self.stop_path = Path(stop_path)
        self.health = CollectorHealth()
        self._stop_event = threading.Event()
        self.correlator = DnsCorrelator()

    def _write_health(self) -> None:
        snapshot = self.health.snapshot()
        snapshot["pid"] = os.getpid()
        self.health_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.health_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(snapshot, default=str), encoding="utf-8")
        temporary.replace(self.health_path)

    def stop(self) -> None:
        """Request a graceful stop after the current capture interval."""
        self._stop_event.set()

    def handle_packet(self, packet: object) -> None:
        """Parse and persist one captured packet."""
        with self.health._lock:
            self.health.packets_seen += 1
        self._write_health()
        event = packet_to_event(packet)
        if event is None:
            with self.health._lock:
                self.health.malformed_packets += 1
            return
        insert_event(self.database_path, self.correlator.observe(event))
        with self.health._lock:
            self.health.events_persisted += 1
            self.health.last_event_at = event.observed_at
        self._write_health()

    def run(self) -> None:
        """Run until stop is requested, updating health state throughout."""
        self.stop_path.unlink(missing_ok=True)
        initialize_database(self.database_path)
        with self.health._lock:
            self.health.status = "running"
            self.health.started_at = datetime.now(timezone.utc)
        self._write_health()
        try:
            while not self._stop_event.is_set() and not self.stop_path.exists():
                sniff(
                    iface=self.interface,
                    filter=self.packet_filter,
                    prn=self.handle_packet,
                    store=False,
                    timeout=1,
                )
                self._write_health()
        except Exception as error:
            with self.health._lock:
                self.health.status = "error"
                self.health.error = str(error)
            self._write_health()
            LOGGER.exception("DNS collector stopped with an error")
            raise
        finally:
            with self.health._lock:
                self.health.status = "stopped"
                self.health.stopped_at = datetime.now(timezone.utc)
            self._write_health()


def load_settings(path: str | Path) -> dict[str, object]:
    """Load collector settings from the project YAML configuration."""
    with Path(path).open(encoding="utf-8") as settings_file:
        settings = yaml.safe_load(settings_file)
    if not isinstance(settings, dict):
        raise ValueError(f"Invalid settings file: {path}")
    return settings


def collector_from_settings(path: str | Path) -> DnsCollector:
    settings = load_settings(path)
    capture = settings.get("capture")
    if not isinstance(capture, dict):
        raise ValueError("Settings must define a capture mapping")
    database_path = settings.get("database_path")
    if not isinstance(database_path, str):
        raise ValueError("Settings must define database_path")
    interface = capture.get("interface")
    packet_filter = capture.get("filter")
    if not isinstance(interface, str) or not isinstance(packet_filter, str):
        raise ValueError("Capture settings require interface and filter strings")
    health_path = settings.get("health_path", "outputs/collector_health.json")
    if not isinstance(health_path, str):
        raise ValueError("Settings health_path must be a string")
    stop_path = settings.get("stop_path", "outputs/collector.stop")
    if not isinstance(stop_path, str):
        raise ValueError("Settings stop_path must be a string")
    return DnsCollector(interface, packet_filter, database_path, health_path, stop_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Windows DNS Sentinel collector")
    parser.add_argument("--config", default="config/settings.yaml")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    collector = collector_from_settings(args.config)
    try:
        collector.run()
    except KeyboardInterrupt:
        collector.stop()
        LOGGER.info("DNS collector stopped by user")


if __name__ == "__main__":
    main()
