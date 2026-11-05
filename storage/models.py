"""Canonical data structures used by the storage layer."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DnsEvent:
    event_id: str
    observed_at: datetime
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    transport: str
    transaction_id: int
    qname: str
    qtype: str
    is_response: bool
    response_code: int | None = None
    answers_json: str = "[]"
    ttl: int | None = None
    correlation_status: str = "unclassified"

