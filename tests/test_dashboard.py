import json
import pandas as pd

from dashboard import collector_running, format_event_timestamps, load_health, workstation_queries


def test_load_health_handles_missing_file(tmp_path):
    assert load_health(tmp_path / "missing.json")["status"] == "not_started"


def test_load_health_reads_status(tmp_path):
    health_path = tmp_path / "health.json"
    health_path.write_text(json.dumps({"status": "running", "pid": 123}), encoding="utf-8")
    assert load_health(health_path)["status"] == "running"


def test_collector_running_rejects_missing_pid():
    assert not collector_running({"status": "running"})


def test_collector_running_rejects_non_running_status():
    assert not collector_running({"status": "stopped", "pid": 1})


def test_event_timestamps_are_formatted_in_ist():
    events = pd.DataFrame({"observed_at": ["2026-11-05T10:00:00+00:00"]})
    assert format_event_timestamps(events).iloc[0, 0] == "05 Nov 2026, 03:30:00 PM IST"


def test_workstation_queries_exclude_responses():
    events = pd.DataFrame({"is_response": [False, True], "qname": ["example.com", "example.com"]})
    assert len(workstation_queries(events)) == 1
    assert not workstation_queries(events).iloc[0]["is_response"]
