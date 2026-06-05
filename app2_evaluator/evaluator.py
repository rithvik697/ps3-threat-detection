"""
APP 2 - LOG EVALUATOR
Reads logs from App 1, detects anomalies (brute-force, port scan),
correlates affected software/version with cached CVEs, emits prioritized alerts.

Run:  python evaluator.py --logs ../data/logs.json --cve ../data/cve_cache.json
"""
import json, argparse
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 50   # failures from one IP -> brute-force suspicion

def load(path):
    return json.load(open(path))

# ---------------------------------------------------------------- detection
def detect_brute_force(logs):
    fails = defaultdict(list)
    for l in logs:
        if l.get("service") == "sshd" and l.get("event") == "auth" and l.get("status") == "failed":
            fails[(l["source_ip"], l["host"])].append(l)
    findings = []
    for (ip, host), entries in fails.items():
        if len(entries) >= FAILED_LOGIN_THRESHOLD:
            # did a success follow from same IP/host?
            success = any(
                l["source_ip"] == ip and l["host"] == host
                and l["service"] == "sshd" and l["status"] == "success"
                for l in logs
            )
            findings.append({
                "type": "Brute Force" + (" (SUCCESSFUL)" if success else ""),
                "ip": ip, "host": host, "count": len(entries),
                "version": entries[0].get("version", "-"),
                "breached": success,
            })
    return findings

def detect_port_scan(logs):
    probes = defaultdict(set)
    for l in logs:
        if str(l.get("event", "")).startswith("port_probe"):
            probes[l["source_ip"]].add(l["event"])
    return [{"type": "Port Scan", "ip": ip, "host": "firewall",
             "count": len(ports), "version": "-", "breached": False}
            for ip, ports in probes.items() if len(ports) >= 5]

# ---------------------------------------------------------------- CVE correlation
def correlate(finding, cves):
    v = finding.get("version", "-")
    return [c for c in cves if v in c.get("affected_versions", [])]

# ---------------------------------------------------------------- alerts
def build_alert(finding, matched):
    sev = "HIGH" if finding["breached"] else "MEDIUM"
    if matched:
        top = max(matched, key=lambda c: c["cvss"])
        sev = top["severity"]
        cve_line = (f' \u2014 matches {top["id"]} (CVSS {top["cvss"]}). '
                    f'{top["recommended_action"]}')
    else:
        cve_line = " \u2014 no matching CVE in cache."
    return {
        "severity": sev,
        "title": f'{finding["type"]} on {finding["host"]} from {finding["ip"]}',
        "detail": (f'{finding["count"]} events; affected software {finding["version"]}'
                   f'{cve_line}'),
        "cves": [c["id"] for c in matched],
    }

def evaluate(logs, cves):
    findings = detect_brute_force(logs) + detect_port_scan(logs)
    alerts = [build_alert(f, correlate(f, cves)) for f in findings]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: order.get(a["severity"], 3))
    return alerts

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="../data/logs.json")
    ap.add_argument("--cve", default="../data/cve_cache.json")
    a = ap.parse_args()
    alerts = evaluate(load(a.logs), load(a.cve))
    print(f"\n=== {len(alerts)} ALERT(S) ===\n")
    for al in alerts:
        print(f'[{al["severity"]}] {al["title"]}')
        print(f'   {al["detail"]}\n')
