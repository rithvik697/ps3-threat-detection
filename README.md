# CVE-Aware Security Log Threat Detection

A two-part security pipeline built for a hackathon problem statement. **App 1** generates realistic
security logs with configurable attack patterns injected. **App 2** ingests those logs, detects
anomalies, correlates findings against known CVEs, and emits prioritised, explainable incidents.

Python, stdlib-only detection core, Streamlit UI.

---

## Result

On a 50,000-line generated log set, the initial per-event detection produced **3,415 alerts** —
unusable for an analyst. After reworking detection around campaign aggregation and behavioural
profiling, the same input produces **3 accurate incidents**.

What changed:

- **Campaign aggregation** — one incident per attacker/campaign instead of one per event.
  3,367 SQL-injection events collapse into a single `CRITICAL` incident attributed to the real
  attacker; distributed port scans and failed-login surges each aggregate into one finding.
- **Behavioural layer** — only profile IPs with at least `ANOMALY_MIN_EVENTS` events. This removes
  the one-off-IP flood while still catching concentrated attacks (a credential spray was detected
  at 40.7σ).

---

## Architecture

```
        ┌──────────────────────┐
        │  APP 1: GENERATOR    │
        │  normal + attack     │
        │  patterns, config'd  │
        └──────────┬───────────┘
                   │  logs.json / .csv / .syslog
                   │  { timestamp, source_ip, host,
                   │    service, version, event, status }
                   ▼
        ┌──────────────────────┐      ┌──────────────────┐
        │  APP 2: EVALUATOR    │◄─────│  NVD 2.0 API     │
        │  1. detect_all       │      │  (live)          │
        │  2. correlate        │      │  + cached snap   │
        │  3. prioritise       │      └──────────────────┘
        └──────────┬───────────┘
                   │  prioritised incidents
                   ▼
        ┌──────────────────────┐
        │  severity + CVE +    │
        │  recommended action  │
        └──────────────────────┘
```

The evaluator runs as explicit ordered phases — `detect_all` → `correlate_findings` → `prioritise`
— so detection is fully decoupled from CVE correlation.

---

## CVE correlation

- `--live` pulls current CVEs from the **NVD 2.0 API** at runtime, reading `totalResults` and
  fetching the newest page, then ranking by recency and severity so the top match is current
  rather than a stale max-CVSS artifact.
- Falls back automatically to a cached snapshot on any failure.
- `--refresh-cve` rebuilds the local cache from a live NVD pull.
- `cve_source` is recorded in the evidence and shown in output, so every correlation is traceable
  to where it came from.
- Correlation is per-attack-type rather than blanket: credential attacks map to SSH/22,
  SQL injection to database and web services, and port scans — being reconnaissance — get no
  forced CVE, with the scanned ports carried in the evidence instead.

Uses `urllib` from the standard library; no HTTP dependencies.

---

## Detection

| Rule | Trigger |
|---|---|
| Brute force | ≥50 failed SSH logins from one IP against one host; escalated to `HIGH` if a success from the same IP follows |
| Port scan | one IP probing ≥5 distinct ports |
| SQL injection | labelled injection events, aggregated per attacker campaign |
| Behavioural anomaly | statistical profiling of IPs above an event threshold |

Severity ordering includes `CRITICAL`; the CVE cache is enriched for Tomcat, MySQL and PostgreSQL
alongside the base OpenSSH entries.

---

## Log schema

Both applications agree on this contract:

```json
{
  "timestamp": "...",
  "source_ip": "...",
  "host": "...",
  "service": "...",
  "version": "...",
  "event": "...",
  "status": "..."
}
```

---

## Running it

```bash
# optional — only for the web UI
pip install streamlit

# 1. generate logs with attacks injected
cd app1_generator
python generator.py --lines 50000 --attacks brute_force,port_scan --out ../data/logs.json

# 2. evaluate, correlating against the cached CVE snapshot
cd ../app2_evaluator
python evaluator.py --logs ../data/logs.json --cve ../data/cve_cache.json

# or correlate against live NVD data
python evaluator.py --logs ../data/logs.json --live
```

---

## Layout

```
├── app1_generator/     # log generation: templates, multi-source events, attack injection
├── app2_evaluator/     # config / models / stats | detectors | correlation | incidents | CLI
├── data/               # generated logs + CVE cache
└── run.sh
```

The evaluator is split into focused modules — shared `config`/`models`/`stats`, then `detectors`,
`correlation`, `incidents`, and an `evaluator` CLI that re-exports for backwards compatibility.

---

## My contribution

I built the **App 2 evaluator side**: the detection engine, the campaign-aggregation and
behavioural layers described above, the NVD live-correlation path with cache fallback, and the
modular refactor of the evaluator pipeline.

Built during the Aiden AI hackathon, June 2026.
