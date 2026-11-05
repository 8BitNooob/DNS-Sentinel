"""Alert deduplication and incident grouping."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass(frozen=True)
class AlertObservation:
    observed_at: datetime
    client_ip: str
    domain: str
    rule: str
    evidence: str
    score: int


@dataclass
class Incident:
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    client_ip: str
    domain: str
    rules: set[str] = field(default_factory=set)
    observations: list[AlertObservation] = field(default_factory=list)
    score: int = 0


class IncidentGrouper:
    def __init__(self, *, grouping_seconds: int = 300):
        self.window = timedelta(seconds=grouping_seconds)
        self.incidents: dict[str, Incident] = {}

    def add(self, observation: AlertObservation) -> Incident:
        for incident in self.incidents.values():
            if (
                incident.client_ip == observation.client_ip
                and incident.domain == observation.domain
                and observation.observed_at - incident.last_seen <= self.window
            ):
                if observation.rule in incident.rules and observation.evidence == incident.observations[-1].evidence:
                    return incident
                incident.last_seen = observation.observed_at
                incident.rules.add(observation.rule)
                incident.observations.append(observation)
                incident.score = max(incident.score, observation.score)
                return incident
        incident_id = f"{observation.client_ip}|{observation.domain}|{observation.observed_at.isoformat()}"
        incident = Incident(
            incident_id=incident_id, first_seen=observation.observed_at, last_seen=observation.observed_at,
            client_ip=observation.client_ip, domain=observation.domain,
            rules={observation.rule}, observations=[observation], score=observation.score,
        )
        self.incidents[incident_id] = incident
        return incident

