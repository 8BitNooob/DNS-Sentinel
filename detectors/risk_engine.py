"""Configurable, explainable 0-100 prioritization scoring."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskContribution:
    rule: str
    points: int
    evidence: str


@dataclass(frozen=True)
class RiskResult:
    score: int
    contributions: tuple[RiskContribution, ...]


DEFAULT_WEIGHTS = {
    "long_domain": 10,
    "long_label": 10,
    "high_entropy_label": 12,
    "high_query_rate": 15,
    "high_nxdomain_rate": 15,
    "tunneling_like_behavior": 30,
    "answer_set_change": 12,
    "ttl_change": 6,
    "protocol_validation": 10,
}


def calculate_risk(alerts, *, weights: dict[str, int] | None = None) -> RiskResult:
    configured = weights or DEFAULT_WEIGHTS
    contributions = tuple(
        RiskContribution(alert.rule, configured.get(alert.rule, 0), alert.evidence)
        for alert in alerts
        if configured.get(alert.rule, 0) > 0
    )
    return RiskResult(score=min(100, sum(item.points for item in contributions)), contributions=contributions)

