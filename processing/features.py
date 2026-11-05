"""Feature extraction shared by live and offline DNS processing."""

import math
from collections import Counter
from dataclasses import dataclass
import tldextract

from storage.models import DnsEvent


@dataclass(frozen=True)
class DnsFeatures:
    domain_length: int
    max_label_length: int
    label_entropy: float
    registered_domain: str
    client_query_rate: float
    nxdomain_rate: float


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def extract_features(event: DnsEvent, history: list[DnsEvent] | None = None) -> DnsFeatures:
    history = history or [event]
    labels = [label for label in event.qname.split(".") if label]
    registered = tldextract.extract(event.qname).top_domain_under_public_suffix
    start = min(item.observed_at for item in history)
    end = max(item.observed_at for item in history)
    duration = max((end - start).total_seconds(), 1.0)
    queries = [item for item in history if not item.is_response]
    responses = [item for item in history if item.is_response and item.response_code is not None]
    nxdomain = sum(item.response_code == 3 for item in responses)
    return DnsFeatures(
        domain_length=len(event.qname),
        max_label_length=max(map(len, labels), default=0),
        label_entropy=_entropy(max(labels, key=len, default="")),
        registered_domain=registered,
        client_query_rate=len(queries) / duration * 60,
        nxdomain_rate=nxdomain / len(responses) if responses else 0.0,
    )
