import json
from dashboard import collector_running, load_health


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
