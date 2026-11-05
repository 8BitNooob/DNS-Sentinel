"""Rolling client baselines with minimum samples and burst protection."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import median

from storage.models import DnsEvent


@dataclass(frozen=True)
class ClientBaseline:
    client_ip: str
    sample_count: int
    query_rate_median: float
    unique_domain_median: float
    nxdomain_rate_median: float
    trusted: bool


class BaselineTracker:
    def __init__(self, *, window_seconds: int = 300, max_samples: int = 100, minimum_samples: int = 5):
        if min(window_seconds, max_samples, minimum_samples) <= 0:
            raise ValueError("Baseline limits must be positive")
        self.window = timedelta(seconds=window_seconds)
        self.max_samples = max_samples
        self.minimum_samples = minimum_samples
        self._samples: dict[str, deque[tuple[datetime, float, float, float]]] = defaultdict(
            lambda: deque(maxlen=max_samples)
        )

    def observe(
        self,
        client_ip: str,
        observed_at: datetime,
        *,
        query_rate: float,
        unique_domains: float,
        nxdomain_rate: float,
        suspicious: bool = False,
    ) -> ClientBaseline:
        samples = self._samples[client_ip]
        cutoff = observed_at - self.window
        while samples and samples[0][0] < cutoff:
            samples.popleft()
        if not suspicious:
            samples.append((observed_at, query_rate, unique_domains, nxdomain_rate))
        return self.snapshot(client_ip)

    def snapshot(self, client_ip: str) -> ClientBaseline:
        samples = self._samples[client_ip]
        trusted = len(samples) >= self.minimum_samples
        query_rates = [sample[1] for sample in samples]
        unique_domains = [sample[2] for sample in samples]
        nxdomain_rates = [sample[3] for sample in samples]
        return ClientBaseline(
            client_ip=client_ip,
            sample_count=len(samples),
            query_rate_median=median(query_rates) if query_rates else 0.0,
            unique_domain_median=median(unique_domains) if unique_domains else 0.0,
            nxdomain_rate_median=median(nxdomain_rates) if nxdomain_rates else 0.0,
            trusted=trusted,
        )
