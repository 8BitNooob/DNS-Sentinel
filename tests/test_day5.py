from datetime import datetime, timedelta, timezone

from detectors.risk_engine import calculate_risk
from incidents.allowlist import Allowlist, AllowlistEntry
from incidents.grouping import AlertObservation, IncidentGrouper
from processing.baselines import BaselineTracker
from storage.day5 import count_day5_rows, save_baseline


def test_baseline_requires_samples_and_ignores_suspicious_bursts():
    tracker = BaselineTracker(minimum_samples=2)
    now = datetime.now(timezone.utc)
    tracker.observe("10.0.0.1", now, query_rate=10, unique_domains=2, nxdomain_rate=0)
    baseline = tracker.observe("10.0.0.1", now, query_rate=12, unique_domains=3, nxdomain_rate=0.1)
    assert baseline.trusted
    before = baseline.sample_count
    after = tracker.observe("10.0.0.1", now, query_rate=1000, unique_domains=1000, nxdomain_rate=1, suspicious=True)
    assert after.sample_count == before


def test_risk_is_capped_and_explainable():
    alerts = [type("Alert", (), {"rule": "tunneling_like_behavior", "evidence": "signals=a,b"})(),
              type("Alert", (), {"rule": "high_query_rate", "evidence": "per_minute=100"})()]
    result = calculate_risk(alerts)
    assert result.score == 45
    assert [item.rule for item in result.contributions] == ["tunneling_like_behavior", "high_query_rate"]


def test_incident_grouping_deduplicates_and_allowlist_expires():
    now = datetime.now(timezone.utc)
    grouper = IncidentGrouper()
    first = AlertObservation(now, "10.0.0.1", "example.com", "long_label", "length=60", 10)
    duplicate = AlertObservation(now + timedelta(seconds=1), "10.0.0.1", "example.com", "long_label", "length=60", 10)
    incident = grouper.add(first)
    assert grouper.add(duplicate) is incident
    assert len(incident.observations) == 1
    allowlist = Allowlist()
    allowlist.add(AllowlistEntry("domain", "example.com", None, now + timedelta(seconds=1), "known service"))
    assert allowlist.suppresses(domain="example.com", client="10.0.0.1", detector="long_label", now=now)
    assert not allowlist.suppresses(domain="example.com", client="10.0.0.1", detector="long_label", now=now + timedelta(seconds=2))


def test_day5_database_survives_reopen(tmp_path):
    database = tmp_path / "day5.sqlite3"
    tracker = BaselineTracker(minimum_samples=1)
    baseline = tracker.observe("10.0.0.1", datetime.now(timezone.utc), query_rate=1, unique_domains=1, nxdomain_rate=0)
    save_baseline(database, baseline, datetime.now(timezone.utc).isoformat())
    assert count_day5_rows(database, "client_baselines") == 1
    assert count_day5_rows(database, "client_baselines") == 1
