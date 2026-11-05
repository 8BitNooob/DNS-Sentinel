"""Explainable tunneling-like indicators for a client and registered domain."""

import statistics
from dataclasses import dataclass

import tldextract

from processing.features import _entropy
from storage.models import DnsEvent


@dataclass(frozen=True)
class TunnelingFeatures:
    client_ip: str
    registered_domain: str
    query_volume: int
    unique_subdomain_count: int
    unique_subdomain_ratio: float
    txt_share: float
    average_label_length: float
    maximum_label_length: int
    average_entropy: float
    average_interarrival_seconds: float
    periodicity_score: float
    nxdomain_share: float


@dataclass(frozen=True)
class TunnelingAlert:
    rule: str
    evidence: str


def _registered_domain(qname: str) -> str:
    return tldextract.extract(qname).top_domain_under_public_suffix


def calculate_tunneling_features(events: list[DnsEvent]) -> TunnelingFeatures:
    queries = sorted((event for event in events if not event.is_response), key=lambda item: item.observed_at)
    if not queries:
        raise ValueError("At least one DNS query is required")
    registered = _registered_domain(queries[0].qname)
    client = queries[0].source_ip
    subdomains = {
        event.qname[: -(len(registered) + 1)]
        for event in queries
        if _registered_domain(event.qname) == registered and event.qname != registered
    }
    labels = [label for event in queries for label in event.qname.split(".")[:-2] if label]
    intervals = [
        (right.observed_at - left.observed_at).total_seconds()
        for left, right in zip(queries, queries[1:])
    ]
    txt_share = sum(event.qtype.upper() == "TXT" for event in queries) / len(queries)
    response_events = [event for event in events if event.is_response and event.response_code is not None]
    nxdomain_share = sum(event.response_code == 3 for event in response_events) / len(response_events) if response_events else 0.0
    periodicity = 0.0
    if len(intervals) >= 3 and statistics.mean(intervals) > 0:
        periodicity = 1 - statistics.pstdev(intervals) / statistics.mean(intervals)
        periodicity = max(0.0, min(1.0, periodicity))
    return TunnelingFeatures(
        client_ip=client,
        registered_domain=registered,
        query_volume=len(queries),
        unique_subdomain_count=len(subdomains),
        unique_subdomain_ratio=len(subdomains) / len(queries),
        txt_share=txt_share,
        average_label_length=statistics.mean(map(len, labels)) if labels else 0.0,
        maximum_label_length=max(map(len, labels), default=0),
        average_entropy=statistics.mean(map(_entropy, labels)) if labels else 0.0,
        average_interarrival_seconds=statistics.mean(intervals) if intervals else 0.0,
        periodicity_score=periodicity,
        nxdomain_share=nxdomain_share,
    )


def evaluate_tunneling_indicators(
    features: TunnelingFeatures,
    *,
    minimum_queries: int = 10,
    unique_ratio: float = 0.8,
    txt_share: float = 0.5,
    average_label_length: float = 25.0,
    entropy: float = 3.5,
    periodicity: float = 0.9,
) -> list[TunnelingAlert]:
    if features.query_volume < minimum_queries:
        return []
    signals: list[TunnelingAlert] = []
    if features.unique_subdomain_ratio >= unique_ratio:
        signals.append(TunnelingAlert("unique_subdomain_ratio", f"ratio={features.unique_subdomain_ratio:.2%}"))
    if features.txt_share >= txt_share:
        signals.append(TunnelingAlert("txt_query_share", f"share={features.txt_share:.2%}"))
    if features.average_label_length >= average_label_length:
        signals.append(TunnelingAlert("average_label_length", f"average={features.average_label_length:.2f}"))
    if features.average_entropy >= entropy:
        signals.append(TunnelingAlert("entropy_distribution", f"average={features.average_entropy:.2f}"))
    if features.periodicity_score >= periodicity:
        signals.append(TunnelingAlert("periodicity", f"score={features.periodicity_score:.2f}"))
    if features.nxdomain_share >= 0.5:
        signals.append(TunnelingAlert("nxdomain_share", f"share={features.nxdomain_share:.2%}"))
    if len(signals) < 2:
        return []
    return [
        TunnelingAlert(
            "tunneling_like_behavior",
            f"registered_domain={features.registered_domain}; "
            f"signals={','.join(signal.rule for signal in signals)}",
        )
    ]
