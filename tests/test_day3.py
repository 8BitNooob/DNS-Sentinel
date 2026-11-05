from datetime import datetime, timedelta, timezone

from detectors.basic_rules import evaluate_basic_rules
from processing.correlator import DnsCorrelator
from processing.features import extract_features
from storage.models import DnsEvent


def event(**kwargs):
    defaults = dict(
        event_id="e", observed_at=datetime.now(timezone.utc), source_ip="10.0.0.1",
        source_port=53000, destination_ip="8.8.8.8", destination_port=53,
        transport="udp", transaction_id=1, qname="example.com", qtype="A",
        is_response=False,
    )
    defaults.update(kwargs)
    return DnsEvent(**defaults)


def test_correlator_matches_and_classifies_duplicates():
    correlator = DnsCorrelator()
    query = correlator.observe(event())
    response = correlator.observe(event(event_id="r", is_response=True, source_ip="8.8.8.8",
                                         destination_ip="10.0.0.1", source_port=53, destination_port=53000))
    duplicate = correlator.observe(event(event_id="r2", is_response=True, source_ip="8.8.8.8",
                                          destination_ip="10.0.0.1", source_port=53, destination_port=53000))
    assert query.correlation_status == "pending"
    assert response.correlation_status == "matched"
    assert duplicate.correlation_status == "duplicate_response"


def test_correlator_expires_queries_and_bounds_pending():
    correlator = DnsCorrelator(expiry_seconds=1, max_pending=1)
    first = correlator.observe(event())
    second = correlator.observe(event(event_id="e2", transaction_id=2))
    assert first.correlation_status == "pending"
    assert second.correlation_status == "pending"
    expired = correlator.observe(event(event_id="e3", transaction_id=3,
                                        observed_at=first.observed_at + timedelta(seconds=2)))
    assert expired.correlation_status == "pending"
    assert len(correlator.pending) == 1


def test_features_and_basic_rules():
    current = event(qname="ab12cd34ef56gh78.example.com", observed_at=datetime.now(timezone.utc))
    history = [current] + [
        event(event_id=f"r{i}", is_response=True, source_ip="8.8.8.8",
              destination_ip="10.0.0.1", source_port=53, destination_port=53000,
              response_code=3, observed_at=current.observed_at + timedelta(seconds=i))
        for i in range(20)
    ]
    features = extract_features(current, history)
    alerts = evaluate_basic_rules(features, minimum_nxdomain_responses=20, response_count=20)
    assert features.registered_domain == "example.com"
    assert any(alert.rule == "high_nxdomain_rate" for alert in alerts)
