"""Explainable basic DNS anomaly rules."""

from dataclasses import dataclass

from processing.features import DnsFeatures


@dataclass(frozen=True)
class RuleAlert:
    rule: str
    evidence: str


def evaluate_basic_rules(
    features: DnsFeatures,
    *,
    full_domain_length: int = 100,
    label_length: int = 50,
    entropy: float = 3.5,
    query_rate: float = 60,
    nxdomain_rate: float = 0.5,
    minimum_nxdomain_responses: int = 20,
    response_count: int = 0,
) -> list[RuleAlert]:
    alerts: list[RuleAlert] = []
    if features.domain_length > full_domain_length:
        alerts.append(RuleAlert("long_domain", f"length={features.domain_length}"))
    if features.max_label_length > label_length:
        alerts.append(RuleAlert("long_label", f"length={features.max_label_length}"))
    if features.max_label_length >= 12 and features.label_entropy > entropy:
        alerts.append(RuleAlert("high_entropy_label", f"entropy={features.label_entropy:.2f}"))
    if features.client_query_rate > query_rate:
        alerts.append(RuleAlert("high_query_rate", f"per_minute={features.client_query_rate:.2f}"))
    if response_count >= minimum_nxdomain_responses and features.nxdomain_rate > nxdomain_rate:
        alerts.append(RuleAlert("high_nxdomain_rate", f"rate={features.nxdomain_rate:.2%}"))
    return alerts
