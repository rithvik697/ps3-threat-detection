# PS3 — Log Generation & CVE-Aware Threat Detection

Two applications: **App 1** generates realistic security logs with configurable
attacks; **App 2** ingests them, detects anomalies, and correlates findings with
known CVEs to produce prioritized, explainable alerts.

## Quick start
```bash
pip install flask flask-cors          # only needed for the web UI (optional)

# 1. Generate logs (with attacks injected)
cd app1_generator
python generator.py --lines 50000 --attacks brute_force,port_scan --out ../data/logs.json

# 2. Evaluate them
cd ../app2_evaluator
python evaluator.py --logs ../data/logs.json --cve ../data/cve_cache.json
```

## Architecture & data flow
```
                 ┌─────────────────────┐
                 │   APP 1: GENERATOR  │
                 │  normal + attack    │
                 │  patterns, configurable
                 └──────────┬──────────┘
                            │  logs.json / .csv / .syslog
                            │  { timestamp, source_ip, host,
                            │    service, version, event, status }
                            ▼
                 ┌─────────────────────┐      ┌──────────────────┐
                 │   APP 2: EVALUATOR  │◄─────│  cve_cache.json  │
                 │  1. parse logs      │      │  (NVD/MITRE snap)│
                 │  2. detect anomalies│      └──────────────────┘
                 │  3. correlate CVEs  │
                 │  4. prioritize      │
                 └──────────┬──────────┘
                            │  prioritized alerts
                            ▼
                 ┌─────────────────────┐
                 │  ALERT OUTPUT / UI  │
                 │  severity + CVE +   │
                 │  recommended action │
                 └─────────────────────┘
```

## Shared data contract (both apps agree on this)
```json
{ "timestamp": "...", "source_ip": "...", "host": "...",
  "service": "...", "version": "...", "event": "...", "status": "..." }
```

## Detection rules (App 2)
- **Brute force:** ≥50 failed SSH logins from one IP on one host; flagged
  SUCCESSFUL (HIGH) if a success from the same IP follows.
- **Port scan:** one IP probing ≥5 distinct ports.
- **CVE correlation:** match the affected software version against the cached
  CVE list; attach the highest-CVSS match + recommended action.

## Demo trick
App 1 deliberately emits logs using `OpenSSH_7.2p2`, a version present in
`cve_cache.json`. This guarantees a clean, reliable CVE correlation on stage —
no dependency on a live API during the demo. (To show "live" CVE fetching,
swap `cve_cache.json` for a real NVD API call — kept cached here for reliability.)

## Team split (5)

**Generator team (2) — own `generator.py` + Generator tab**
- **G1:** log templates, multi-source events (auth/web/firewall/app), fake IPs, timestamps, CSV/JSON export.
- **G2:** attack patterns (brute force, port scan, SQL injection, suspicious admin login) + volume/time/severity controls.

**Evaluator team (3) — own `evaluator.py` + Evaluator tab**
- **E1 (lead / integration):** detection rules (brute force, port scan, SQL injection, impossible login, privilege escalation); keeps `main` runnable and wires the pipeline together.
- **E2:** CVE correlation — expand `cve_cache.json`, version matching, optional live NVD lookup toggle.
- **E3:** alert building (severity, explanation, recommended action) + Evaluator dashboard (alerts table, severity chart).

## Workflow
- **Stack:** Python + Streamlit (two tabs) over plain logic modules. `pip install streamlit requests`.
- **Contracts (lock before coding):** (1) log schema below; (2) the software version string in generated logs must exactly match a version in `cve_cache.json`.
- **Git:** each person on their own branch → merge to `main`; lead keeps `main` always-runnable.
- **Build order:** push repo → all clone & run baseline → lock contracts → build in parallel → integrate into Streamlit tabs → freeze, polish, rehearse → submit.
