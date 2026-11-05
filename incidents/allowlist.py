"""Expiring domain, client, and detector suppression rules."""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class AllowlistEntry:
    kind: str
    value: str
    detector: str | None
    expires_at: datetime
    reason: str


class Allowlist:
    def __init__(self) -> None:
        self._entries: list[AllowlistEntry] = []

    def add(self, entry: AllowlistEntry) -> None:
        if entry.kind not in {"domain", "client", "detector"} or not entry.reason.strip():
            raise ValueError("Allowlist entries require a valid kind and reason")
        self._entries.append(entry)

    def suppresses(self, *, domain: str, client: str, detector: str, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        self._entries = [entry for entry in self._entries if entry.expires_at > current]
        return any(
            (entry.kind == "domain" and entry.value == domain)
            or (entry.kind == "client" and entry.value == client)
            or (entry.kind == "detector" and entry.value == detector)
            for entry in self._entries
            if entry.detector is None or entry.detector == detector
        )

