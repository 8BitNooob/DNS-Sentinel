"""DNS answer-history consistency signals, not spoofing conclusions."""

import json
from dataclasses import dataclass

from storage.models import DnsEvent


@dataclass(frozen=True)
class ResponseConsistencyAlert:
    rule: str
    evidence: str
    investigation_signal: bool = True


def _answer_set(event: DnsEvent) -> frozenset[str]:
    try:
        records = json.loads(event.answers_json)
    except json.JSONDecodeError:
        return frozenset()
    return frozenset(f"{record.get('type')}:{record.get('data')}" for record in records)


class AnswerHistory:
    def __init__(self) -> None:
        self._history: dict[tuple[str, str], tuple[frozenset[str], int | None]] = {}

    def observe(
        self,
        event: DnsEvent,
        *,
        trusted_answers: frozenset[str] | None = None,
        trusted_ttl: int | None = None,
    ) -> list[ResponseConsistencyAlert]:
        if not event.is_response:
            return []
        key = (event.qname, event.qtype)
        answers = _answer_set(event)
        previous = self._history.get(key)
        alerts: list[ResponseConsistencyAlert] = []
        if previous and previous[0] != answers:
            alerts.append(ResponseConsistencyAlert("answer_set_change", f"domain={event.qname}"))
        if previous and previous[1] != event.ttl:
            alerts.append(ResponseConsistencyAlert("ttl_change", f"previous={previous[1]} current={event.ttl}"))
        if trusted_answers is not None and answers != trusted_answers:
            alerts.append(ResponseConsistencyAlert("trusted_answer_mismatch", f"domain={event.qname}"))
        if trusted_ttl is not None and event.ttl != trusted_ttl:
            alerts.append(ResponseConsistencyAlert("trusted_ttl_mismatch", f"expected={trusted_ttl} current={event.ttl}"))
        self._history[key] = (answers, event.ttl)
        return alerts
