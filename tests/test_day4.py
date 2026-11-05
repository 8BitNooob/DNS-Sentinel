import json
from datetime import datetime, timedelta, timezone

from detectors.response_consistency import AnswerHistory
from processing.correlator import DnsCorrelator
from processing.protocol_validation import validate_event
from processing.tunneling import calculate_tunneling_features, evaluate_tunneling_indicators
from storage.models import DnsEvent


def make_event(index=0, **kwargs):
    values = dict(
        event_id=f"e{index}", observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index),
        source_ip="10.0.0.1", source_port=53000 + index, destination_ip="8.8.8.8",
        destination_port=53, transport="udp", transaction_id=index, qname=f"label{index}.example.com",
        qtype="TXT", is_response=False,
    )
    values.update(kwargs)
    return DnsEvent(**values)


def test_tunneling_features_combine_indicators():
    events = [make_event(i) for i in range(12)]
    features = calculate_tunneling_features(events)
    alerts = evaluate_tunneling_indicators(features, minimum_queries=10, average_label_length=4)
    assert features.unique_subdomain_ratio == 1
    assert features.txt_share == 1
    assert any(alert.rule == "tunneling_like_behavior" for alert in alerts)


def test_answer_history_flags_changes_and_trusted_mismatch():
    first = make_event(qname="example.com", qtype="A", is_response=True, response_code=0,
                       answers_json=json.dumps([{"type": "A", "data": "1.1.1.1"}]), ttl=60)
    second = make_event(1, qname="example.com", qtype="A", is_response=True, response_code=0,
                        answers_json=json.dumps([{"type": "A", "data": "2.2.2.2"}]), ttl=30)
    history = AnswerHistory()
    assert history.observe(first) == []
    rules = history.observe(second, trusted_answers=frozenset({"A:1.1.1.1"}), trusted_ttl=60)
    assert {rule.rule for rule in rules} == {"answer_set_change", "ttl_change", "trusted_answer_mismatch", "trusted_ttl_mismatch"}


def test_correlator_conflicting_response_and_protocol_validation():
    correlator = DnsCorrelator()
    query = make_event(qtype="A")
    response = make_event(qtype="A", is_response=True, source_ip="8.8.8.8",
                          destination_ip="10.0.0.1", source_port=53, destination_port=53000,
                          response_code=0, answers_json='[{"type":"A","data":"1.1.1.1"}]')
    conflicting = make_event(1, transaction_id=0, qname="label0.example.com", qtype="A", is_response=True, source_ip="8.8.8.8",
                             destination_ip="10.0.0.1", source_port=53, destination_port=53000,
                             response_code=0, answers_json='[{"type":"A","data":"2.2.2.2"}]')
    assert correlator.observe(query).correlation_status == "pending"
    assert correlator.observe(response).correlation_status == "matched"
    assert correlator.observe(conflicting).correlation_status == "conflicting_response"
    malformed = make_event(qname="bad name", source_port=70000)
    assert {issue.rule for issue in validate_event(malformed)} == {"malformed_qname", "invalid_port"}
