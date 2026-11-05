"""Validation for canonical DNS transaction observations."""

from dataclasses import dataclass
import re

from storage.models import DnsEvent


@dataclass(frozen=True)
class ProtocolIssue:
    rule: str
    evidence: str


def validate_event(event: DnsEvent) -> list[ProtocolIssue]:
    issues: list[ProtocolIssue] = []
    if not event.qname or len(event.qname) > 253:
        issues.append(ProtocolIssue("malformed_qname", f"length={len(event.qname)}"))
    if event.qname and not re.fullmatch(r"[a-z0-9_.*-]+(?:\.[a-z0-9_*-]+)*", event.qname, re.IGNORECASE):
        issues.append(ProtocolIssue("malformed_qname", "invalid DNS label characters"))
    if not 0 <= event.transaction_id <= 65535:
        issues.append(ProtocolIssue("invalid_transaction_id", str(event.transaction_id)))
    if event.source_port < 0 or event.source_port > 65535 or event.destination_port < 0 or event.destination_port > 65535:
        issues.append(ProtocolIssue("invalid_port", f"{event.source_port}->{event.destination_port}"))
    if event.is_response and event.response_code is None:
        issues.append(ProtocolIssue("missing_response_code", event.qname))
    return issues
