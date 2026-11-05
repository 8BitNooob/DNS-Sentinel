"""Bounded DNS query/response correlation."""

from dataclasses import replace
from datetime import timedelta

from storage.models import DnsEvent


class DnsCorrelator:
    def __init__(self, expiry_seconds: float = 10.0, max_pending: int = 10000):
        if expiry_seconds <= 0 or max_pending <= 0:
            raise ValueError("Correlation bounds must be positive")
        self.expiry = timedelta(seconds=expiry_seconds)
        self.max_pending = max_pending
        self.pending: dict[tuple[str, int, str, str, str], DnsEvent] = {}
        self.completed: dict[tuple[str, int, str, str, str], DnsEvent] = {}

    @staticmethod
    def _key(event: DnsEvent) -> tuple[str, int, str, str, str]:
        if event.is_response:
            client, resolver = event.destination_ip, event.source_ip
        else:
            client, resolver = event.source_ip, event.destination_ip
        return client, event.transaction_id, event.qname, event.qtype, event.transport

    def _expire(self, now) -> None:
        expired = [
            key for key, event in self.pending.items()
            if now - event.observed_at > self.expiry
        ]
        for key in expired:
            event = self.pending.pop(key)
            self.completed[key] = replace(event, correlation_status="unmatched_query")

    def observe(self, event: DnsEvent) -> DnsEvent:
        self._expire(event.observed_at)
        key = self._key(event)
        if not event.is_response:
            if key in self.pending:
                return replace(event, correlation_status="duplicate_query")
            if len(self.pending) >= self.max_pending:
                oldest_key = min(self.pending, key=lambda item: self.pending[item].observed_at)
                self.pending.pop(oldest_key)
            self.pending[key] = event
            return replace(event, correlation_status="pending")

        query = self.pending.pop(key, None)
        if query is None:
            if key in self.completed:
                previous = self.completed[key]
                if (previous.answers_json, previous.response_code, previous.ttl) != (
                    event.answers_json, event.response_code, event.ttl
                ):
                    return replace(event, correlation_status="conflicting_response")
                return replace(event, correlation_status="duplicate_response")
            return replace(event, correlation_status="unmatched_response")
        if event.observed_at < query.observed_at:
            return replace(event, correlation_status="conflicting_response")
        self.completed[key] = event
        return replace(event, correlation_status="matched")

    def flush(self) -> list[DnsEvent]:
        events = [replace(event, correlation_status="unmatched_query") for event in self.pending.values()]
        self.pending.clear()
        return events
