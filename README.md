# DNS Sentinel

DNS Sentinel is a local prototype for DNS traffic monitoring, anomaly detection,
and explainable threat analysis. It supports live workstation-visible DNS
collection and offline CSV, PCAP, and Zeek-log processing through a shared
pipeline.

The project is detection and analysis only. It does not block traffic, change
firewall rules, or modify resolver configuration.

## Status

The repository is initialized with the project skeleton described in
[DNS_Sentinel_Workplan_v2.md](./DNS_Sentinel_Workplan_v2.md). Implementation
will follow the seven-day plan, beginning with environment and capture
validation.

## Local setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Npcap is required for Windows live capture. Keep elevated permissions limited
to the collector when required; the dashboard should not run as administrator.

## Project layout

- `collector/`, `processing/`, and `detectors/`: capture and analysis pipeline
- `adapters/`: CSV, PCAP, and Zeek offline inputs
- `storage/`: SQLite persistence
- `incidents/`: grouping and allowlist handling
- `simulation/`: controlled evaluation scenarios
- `tests/`: automated tests
- `config/`: runtime settings and thresholds

See the workplan for architecture, thresholds, limitations, and definition of
done.

