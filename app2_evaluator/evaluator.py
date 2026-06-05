"""
APP 2 - LOG EVALUATOR  (CLI entrypoint)

Reads security events (new schema), runs two-layer detection (signature rules
+ a signature-free behavioral generalizer), correlates the targeted service to
cached CVEs, and emits structured SecurityIncident objects.

The functionality is split across modules:
    config.py       thresholds, schema vocabulary, port->software map
    models.py       SecurityIncident (output contract)
    stats.py        robust statistics (median + MAD)
    detectors.py    the three detectors           (E1)
    correlation.py  CVE correlation               (E2)
    incidents.py    build_incident + evaluate     (E3)

This file just parses args, loads data, and prints/serialises results. The
re-exports below keep `import evaluator as E; E.evaluate(...)` working.

Run:  python evaluator.py --logs ../data/logs.json --cve ../data/cve_cache.json
      python evaluator.py --json        # machine-readable output for the UI
"""
import json, argparse, sys
from dataclasses import asdict

import config
from models import SecurityIncident
from stats import median, robust_z, is_http_error
from detectors import (detect_brute_force, detect_sql_injection,
                       detect_port_scan, detect_failed_logins,
                       detect_statistical_anomalies, detect_ml_anomalies,
                       detect_all)
from correlation import (sev_rank, correlate, fetch_cves_live,
                         resolve_cves, refresh_cache)
from incidents import build_incident, correlate_findings, prioritise, evaluate

# convenience re-exports so existing callers keep working
DEFAULT_LOGS = config.DEFAULT_LOGS
DEFAULT_CVE = config.DEFAULT_CVE

__all__ = [
    "SecurityIncident", "median", "robust_z", "is_http_error",
    "detect_brute_force", "detect_sql_injection", "detect_port_scan",
    "detect_failed_logins", "detect_statistical_anomalies",
    "detect_ml_anomalies", "detect_all",
    "sev_rank", "correlate", "fetch_cves_live", "resolve_cves",
    "refresh_cache", "build_incident", "correlate_findings", "prioritise",
    "evaluate", "load",
]


def load(path):
    return json.load(open(path))


if __name__ == "__main__":
    # Windows consoles default to cp1252, which can't encode chars like 'σ' or
    # '—'. Force UTF-8 so output is correct everywhere (and never crashes).
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default=config.DEFAULT_LOGS)
    ap.add_argument("--cve", default=config.DEFAULT_CVE)
    ap.add_argument("--json", action="store_true", help="emit incidents as JSON")
    ap.add_argument("--live", action="store_true",
                    help="fetch latest CVEs live from NVD (cache fallback)")
    ap.add_argument("--refresh-cve", action="store_true",
                    help="rebuild the CVE cache from a live NVD pull, then exit")
    a = ap.parse_args()

    if a.refresh_cve:
        print("Refreshing CVE cache from NVD ...")
        counts, total = refresh_cache(a.cve)
        for sw, n in counts.items():
            print(f"   {sw:12} {n} CVEs")
        print(f"Wrote {total} CVEs -> {a.cve}" if total else
              "No CVEs fetched (NVD unreachable?) — existing cache left untouched.")
        sys.exit(0)

    incidents = evaluate(load(a.logs), load(a.cve), use_live=a.live)

    if a.json:
        print(json.dumps([asdict(i) for i in incidents], indent=2))
    else:
        print(f"\n=== {len(incidents)} INCIDENT(S) ===\n")
        for inc in incidents:
            ev = inc.evidence
            port = f':{inc.target_port}' if inc.target_port else ''
            print(f'[{ev["severity"]}] ({ev["method"]}) {inc.attack_type} on '
                  f'{inc.target_host}{port} from {", ".join(inc.source_ips)} '
                  f'(confidence {inc.confidence})')
            print(f'   {ev["reason"]}')
            if ev.get("top_cve"):
                print(f'   → {ev["top_cve"]} (CVSS {ev["cvss"]}, via {ev.get("cve_source","cache")})'
                      f' — {ev["recommended_action"]}')
            print()
