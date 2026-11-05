# DNS Sentinel — 7-Day Project Workplan

**Project:** DNS Sentinel: Real-Time DNS Security Monitoring, Anomaly Detection and Threat Analysis System  
**Team:** 2 members | **Timeline:** 7 days | **Environment:** Windows + Ubuntu VM  
**Scope:** Own-workstation DNS traffic initially | **Storage:** SQLite | **Dashboard:** Streamlit  
**Mode:** Detection, monitoring, analysis and alerting only. Prevention and automatic blocking are excluded.

## 1. Objective

Build a prototype that observes DNS traffic visible to the user's own workstation, normalizes DNS events, correlates queries and responses, detects suspicious patterns, stores evidence in SQLite, and displays traffic and alerts in a local Streamlit dashboard. Support both live monitoring and offline CSV, PCAP, and Zeek-log analysis through one shared processing/detection engine.

The collector must run as a separate background process. Streamlit reads from SQLite; refreshing or closing the dashboard must not restart or stop packet collection.

## 2. Finalized architecture

```text
LIVE: Windows (Npcap + Scapy) / Ubuntu (tcpdump, optional Zeek)
                         |
                    DNS parser
                         |
                 Canonical DNS events
                         |
                Query-response correlator
                         |
                   Feature extraction
                         |
       +-----------------+------------------+
       |                 |                  |
   Basic rules     Tunneling indicators   Response consistency
       |                 |                  |
       +-----------------+------------------+
                         |
             Protocol / transaction validation
                         |
                Behavioral baselines
                         |
              Explainable risk scoring
                         |
              Alert and incident grouping
                         |
                      SQLite
                         |
                 Streamlit dashboard

OFFLINE: CSV / PCAP / Zeek logs -> adapters -> same canonical events
                                      -> same processing and detectors
```

## 3. Agreed core features

### Collection and processing
- Background live DNS packet observation on a selected interface.
- Windows capture through Npcap + Scapy.
- Ubuntu tools: tcpdump and Zeek if feasible.
- Offline CSV, PCAP, and Zeek-log ingestion.
- One normalized DNS event schema for live and offline inputs.
- Capture-health and visibility status.

### Basic anomaly detection
- Long full domain names and long individual labels.
- High-entropy subdomain labels.
- High per-client DNS query rate.
- High per-client NXDOMAIN response rate.

### DNS tunneling indicators
- Unique-subdomain count and ratio under a registered domain.
- Average and maximum subdomain-label length.
- Entropy distribution.
- TXT query share.
- Query volume per registered domain.
- NXDOMAIN share.
- Inter-arrival times and periodicity.
- Combine multiple indicators; one weak signal alone should not trigger a definitive claim.

### DNS response inconsistency
- Answer history by domain and record type.
- Unexpected answer IP/address-set changes.
- TTL changes.
- Conflicting answers observed close together.
- Optional trusted static baselines.
- These are investigation signals, not proof of spoofing: CDNs, load balancing, geo-routing, and dynamic DNS can legitimately change answers.

### DNS query-response validation
- Transaction ID, query name/type, flags, endpoints, and timing.
- Validate the relationship between observed query and response.
- Detect unmatched, duplicate, and conflicting responses.
- Basic malformed-message checks.
- Bounded pending-query table with expiry.
- An unmatched response is uncertain evidence: packet loss, late capture start, or asymmetric routing can explain it.

### Behavioral analytics
- Per-client rolling/historical baselines for query rate, unique domains, NXDOMAIN rate, qtype distribution, unique-subdomain ratio, and label lengths.
- Minimum sample requirements.
- Avoid learning suspicious bursts into trusted baselines.
- Start with rolling median/average, standard deviation, or median absolute deviation (MAD).

### Risk and incident management
- Explainable configurable 0–100 risk score; this is a prioritization score, not a probability of compromise.
- Store contributing rules and evidence.
- Avoid double-counting correlated indicators.
- Deduplicate alerts and group related alerts by client/domain/rule family/time.
- Preserve raw evidence.
- Allowlist/suppress by domain, client, or detector with expiry and reason; do not delete underlying events.

### Dashboard
- Overview, Live Traffic, Alerts/Incidents, Client Profiles, Domain Investigation, Offline Analysis, and Settings.
- Collector status, safe local start/stop controls, refresh/polling, charts/tables, and CSV export.
- PDF reports only if time permits.

## 4. Out of scope
- Prevention, automatic blocking, firewall changes, or resolver configuration changes.
- Monitoring other devices or the whole LAN initially.
- Decrypting DoH/DoT.
- Claiming detection of every DNS attack.
- Full DNS cache-poisoning/spoofing prevention.
- Production-grade 24/7 service.

## 5. Technology choices

| Component | Technology |
|---|---|
| Windows live capture | Npcap + Scapy |
| Ubuntu capture/inspection | tcpdump; Zeek if feasible |
| Offline processing | Scapy / Zeek logs |
| Data processing | Python, pandas, NumPy |
| Registered-domain grouping | tldextract |
| Database | SQLite; SQLAlchemy optional |
| Dashboard | Streamlit + Plotly |
| Testing | pytest |
| Inspection | Wireshark |
| Development | Git, VS Code or Antigravity IDE |

Use a public-suffix-aware parser such as `tldextract`. Do not assume the last two labels are always the registered domain (for example, `example.co.uk`).

## 6. Suggested project structure

```text
dns-sentinel/
|-- app.py
|-- requirements.txt
|-- README.md
|-- workplan.md
|-- .gitignore
|-- config/
|   |-- settings.yaml
|   |-- thresholds.yaml
|-- collector/
|   |-- __init__.py
|   |-- capture.py
|   |-- dns_parser.py
|   |-- service.py
|-- processing/
|   |-- __init__.py
|   |-- normalizer.py
|   |-- correlator.py
|   |-- features.py
|-- detectors/
|   |-- __init__.py
|   |-- basic_rules.py
|   |-- tunneling.py
|   |-- response_consistency.py
|   |-- protocol_validation.py
|   |-- behavior.py
|   |-- risk_engine.py
|-- storage/
|   |-- __init__.py
|   |-- database.py
|   |-- models.py
|   |-- repositories.py
|-- incidents/
|   |-- __init__.py
|   |-- grouping.py
|   |-- allowlist.py
|-- adapters/
|   |-- __init__.py
|   |-- csv_adapter.py
|   |-- pcap_adapter.py
|   |-- zeek_adapter.py
|-- simulation/
|   |-- generate_normal.py
|   |-- generate_scenarios.py
|   |-- controlled_dns.py
|-- tests/
|   |-- test_parser.py
|   |-- test_correlator.py
|   |-- test_features.py
|   |-- test_basic_rules.py
|   |-- test_tunneling.py
|   |-- test_response_consistency.py
|   |-- test_protocol_validation.py
|   |-- test_risk_engine.py
|   |-- test_storage.py
|-- data/
|   |-- samples/
|   |-- pcaps/
|-- reports/
|   |-- evaluation.md
|   |-- screenshots/
|-- outputs/
    |-- exports/
```

Do not commit `.venv`, `.env`, secrets, private captures, SQLite databases, large PCAPs, or temporary generated files.

## 7. Seven-day implementation plan

### Day 1 — Environment, architecture skeleton, DNS visibility
1. Create project folder and Git repository.
2. Verify Windows and Python versions.
3. Create/activate a Python virtual environment.
4. Install initial Python dependencies.
5. Install Npcap from its official source.
6. Confirm Ubuntu VM exists and has network access.
7. Install Python and basic packet tools in Ubuntu; install Zeek if feasible.
8. Use Scapy to list Windows interfaces and identify the workstation's active interface.
9. Generate ordinary DNS activity and verify that packets are visible.
10. Save a small, non-sensitive sample PCAP if practical and inspect it in Wireshark.
11. Agree on the normalized DNS event schema.
12. Initialize SQLite and insert/read one sample event.

**Windows commands**
```powershell
mkdir dns-sentinel
cd dns-sentinel
git init
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install scapy pandas numpy streamlit plotly pytest sqlalchemy tldextract
```

If PowerShell blocks activation:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

After Scapy is installed, list interfaces:
```powershell
python -c "from scapy.all import get_if_list; print('\\n'.join(get_if_list()))"
```

**Day 1 deliverable:** Windows/Ubuntu environments checked, Npcap installed, capture interface identified, at least one DNS packet/PCAP inspected, event schema agreed, SQLite initialized.

**Day 1 gate:** Do not build the full detector until the selected capture method demonstrably sees DNS packets generated by your own machine. If live capture is not ready, use offline PCAP temporarily while resolving capture setup.

### Day 2 — Background collector and DNS parsing
1. Implement a standalone collector module.
2. Select capture interface through configuration.
3. Capture only intended workstation-visible traffic.
4. Parse ordinary DNS over UDP/TCP port 53.
5. Extract timestamps, source/destination endpoints, transaction ID, qname, qtype, flags, response code, answers, and TTL where available.
6. Normalize events and persist them to SQLite.
7. Add graceful shutdown and collector-health reporting.
8. Test using DNS lookups generated by the workstation.

**Deliverable:** Background collector persists visible DNS events.

### Day 3 — Correlation, offline adapters, basic rules
1. Implement bounded pending-query cache with expiry.
2. Match query/response using transaction ID, qname/qtype, endpoint relationship, and time.
3. Classify matched, unmatched, duplicate, and conflicting observations.
4. Build CSV, PCAP, and Zeek adapters using the same canonical event format.
5. Extract domain length, label length, entropy, registered domain, rolling query rate, and NXDOMAIN rate.
6. Implement and test the basic rules.
7. Ensure live and offline data use the same detector functions.

**Deliverable:** Shared pipeline, correlation, offline ingestion, and basic rules.

### Day 4 — Tunneling indicators and response security
1. Group queries by client and registered domain.
2. Calculate unique-subdomain count/ratio, TXT share, label-length distribution, entropy, inter-arrival times, and periodicity.
3. Combine indicators into explainable tunneling-like alerts.
4. Maintain answer history by domain and record type.
5. Flag unusual answer-set and TTL changes for investigation.
6. Add trusted baselines if time permits.
7. Test matched, unmatched, duplicate, conflicting, and malformed transaction cases.
8. Document visibility limitations and uncertainty.

**Deliverable:** Tunneling indicators, response inconsistency analysis, and query-response validation.

### Day 5 — Baselines, risk, database, incidents
1. Add per-client rolling baselines and minimum sample requirements.
2. Avoid allowing suspicious bursts to redefine trusted baselines immediately.
3. Implement configurable risk scoring and store score contributions.
4. Group/deduplicate alerts into incidents.
5. Add SQLite tables/indexes for sessions, DNS events, transactions, features, alerts, incidents, client/domain baselines, allowlist, and settings as needed.
6. Implement allowlisting/suppression with expiry and reason.
7. Test persistence across process restarts.

**Deliverable:** Persistent pipeline, baselines, explainable risk score, incident grouping, and false-positive management.

### Day 6 — Streamlit dashboard
1. Build Overview, Live Traffic, Alerts/Incidents, Client Profiles, Domain Investigation, Offline Analysis, and Settings pages.
2. Display collector status from the service/database.
3. Add safe local start/stop controls if feasible.
4. Add refresh/polling, charts, tables, and CSV export.
5. Verify dashboard refresh/closure does not restart or kill the collector.

**Deliverable:** Functional local dashboard.

### Day 7 — Simulation, evaluation, hardening, submission
1. Generate normal browsing-like DNS traces.
2. Generate controlled tunneling-like patterns: long/random labels, many unique subdomains, TXT-heavy and periodic requests.
3. Generate high-volume and repeated-NXDOMAIN scenarios.
4. Generate matched, unmatched, duplicate, and conflicting transaction traces.
5. Generate answer-change traces, including legitimate-looking changes.
6. Test normal-only, scenario-only, and mixed datasets.
7. Measure precision, recall, F1, and false-positive rate where ground truth exists.
8. Measure throughput, collector-to-alert latency, database performance, memory, and packet drops if measurable.
9. Test restart persistence and Windows/Ubuntu workflows.
10. Capture screenshots and prepare README, evaluation notes, and demo.

**Deliverable:** Reproducible prototype, test evidence, screenshots, README, and final report/demo.

## 8. Team split

| Member | Responsibility |
|---|---|
| Member 1 | Capture, parser, correlation, features, detectors, baselines, packet-level tests |
| Member 2 | Setup, SQLite, offline adapters, simulation/test harness, incident grouping, allowlist, dashboard, evaluation/report |

Both members should review the event schema and integration points daily and understand the full pipeline.

## 9. Provisional starting thresholds

These are experimental starting values, not universal standards. Keep them configurable and tune them with normal and simulated traffic.

| Signal | Initial threshold |
|---|---|
| Full domain length | >100 characters |
| Individual label length | >50 characters |
| Label entropy | >3.5 bits/character, with minimum label length |
| Client query rate | >60 queries per 60 seconds |
| NXDOMAIN rate | >50%, with at least 20 completed responses in 5 minutes |

Shannon entropy:
\[
H(X) = -\sum_i p_i \log_2(p_i)
\]

High entropy alone is not proof of malicious activity. Apply a minimum label length and combine multiple indicators.

## 10. Important implementation cautions

- Analyze previously unseen domains too; do not make a static known-domain list the core detector.
- A new or rare domain is not automatically malicious or safe.
- Count NXDOMAIN only from an observed DNS response code. A timeout is not NXDOMAIN.
- Browser/OS DNS caching may mean opening a website produces no new DNS packet.
- Ordinary capture does not reveal DNS names inside encrypted DoH/DoT sessions.
- The workstation sees only packets visible at the selected interface/capture point, not every device on the network.
- Windows and the Ubuntu VM do not automatically see each other's traffic. Network mode affects visibility. Initially monitor each environment's own generated traffic and use the VM for controlled tests/offline PCAP work.
- Keep elevated permissions limited to the collector when required; do not run the whole dashboard as administrator.
- Start with ordinary DNS UDP/TCP port 53 for controlled demonstrations.
- Unmatched response does not prove spoofing; packet loss, late startup, and asymmetric paths can cause it.
- DNS answer changes can be legitimate due to CDNs, load balancing, geo-routing, and dynamic DNS.
- Use public-suffix-aware parsing for registered-domain grouping.
- Describe findings as “suspicious DNS pattern” or “tunneling-like behavior,” not confirmed tunneling, unless independent evidence supports that conclusion.

## 11. Evaluation scenarios

| Scenario | Expected behavior |
|---|---|
| Ordinary browsing-like DNS | No high-severity alert under calibrated thresholds |
| Very long domain/label | Long-name indicator |
| Random-looking long subdomain | Entropy/label indicator; not proof alone |
| High query volume from one client | Rate anomaly |
| Repeated NXDOMAIN responses | NXDOMAIN-rate anomaly |
| Many unique subdomains under one registered domain | Tunneling-like indicator |
| Repeated TXT queries | TXT-share indicator |
| Regularly spaced queries | Periodicity indicator |
| Unexpected answer-set change | Response inconsistency alert for investigation |
| Valid query-response pair | Correctly correlated transaction |
| Unmatched response | Validation warning with uncertainty |
| Duplicate response | Duplicate classification |
| Conflicting response | Conflicting-response classification |
| Legitimate CDN answer changes | Must not automatically be labelled poisoning |

Use a consistent evaluation unit. Query-level rules and client-window rules have different denominators; do not combine them into one misleading metric. Report precision, recall, F1, and false-positive rate only where labels/ground truth are available. Also report throughput, latency, storage growth, and packet drops if measurable.

## 12. Optional features — only after core work
- DNSSEC awareness using validation status reported by a validating resolver/tool; do not implement cryptographic validation from scratch.
- External threat-intelligence lookups, subject to privacy review and rate limits.
- PDF incident reports.
- Isolation Forest or other advanced anomaly algorithms.
- More advanced cross-session baselines.

Do not let optional features delay the core capture → normalize → correlate → detect → persist → dashboard pipeline.

## 13. Definition of done

1. Live collection works for DNS traffic visible on the selected workstation interface, or the limitation is clearly documented and offline mode is demonstrated.
2. CSV/PCAP/Zeek inputs use the same normalized processing pipeline.
3. Correlation handles matched and common unmatched/duplicate/conflicting cases.
4. Basic, tunneling-indicator, response-inconsistency, and protocol-validation features are implemented and tested.
5. Alerts include evidence and explainable risk contributions.
6. SQLite persistence survives restarts.
7. Streamlit displays traffic, alerts, incidents, and investigation details without owning collector lifecycle.
8. Controlled scenarios and normal traffic are evaluated.
9. README, setup steps, limitations, screenshots, and demo instructions are complete.
10. No prevention or automatic blocking feature is included.
