"""
APP 2 - LOG EVALUATOR
Reads logs from App 1, detects anomalies (brute-force, port scan),
correlates affected software/version with cached CVEs, emits prioritized alerts.

Run:  python evaluator.py --logs ../data/logs.json --cve ../data/cve_cache.json
"""
import json, argparse, os, sys
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 50   # failures from one IP -> brute-force suspicion
ANOMALY_Z_THRESHOLD = 3.5     # modified z-score (median/MAD) cutoff for an outlier

# Anchor defaults to <project_root>/data so the script works from any directory.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOGS = os.path.join(PROJECT_ROOT, "data", "logs.json")
DEFAULT_CVE = os.path.join(PROJECT_ROOT, "data", "cve_cache.json")

def load(path):
    return json.load(open(path))

# ---------------------------------------------------------------- robust stats
def _median(xs):
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2

def _robust_z(vals):
    """Modified z-scores using median + MAD (Iglewicz-Hoaglin).

    Robust to the very outliers we hunt: a huge attacker value cannot inflate
    the spread and hide itself — the 'masking' failure mode of mean/std. Falls
    back to mean-absolute-deviation when MAD == 0 (which happens whenever most
    entities share a value, e.g. nearly everyone has zero failures). The 0.6745
    and 1.2533 constants rescale MAD/MeanAD to be comparable to a std-dev, so
    the scores are still readable in 'sigma' units.
    Returns ({key: z}, median-used-as-the-normal-reference).
    """
    xs = list(vals.values())
    med = _median(xs)
    devs = [abs(x - med) for x in xs]
    mad = _median(devs)
    if mad > 0:
        scale = mad / 0.6745
    else:
        meanad = sum(devs) / len(devs)
        scale = 1.2533 * meanad
    z = {k: (0.0 if scale == 0 else (v - med) / scale) for k, v in vals.items()}
    return z, med

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

def detect_statistical_anomalies(logs, z_threshold=ANOMALY_Z_THRESHOLD):
    """Signature-FREE detection: the generalizer.

    The rules above look for KNOWN attack shapes. This instead profiles how
    every source IP behaves, builds a baseline of what "normal" looks like
    across the whole population, and flags any IP that deviates sharply from
    it. Because it models normal rather than specific attacks, it catches
    novel behaviour we never wrote an explicit rule for. No training, no
    labels, fully explainable (every alert states WHICH metric was abnormal
    and by how much).
    """
    # 1. Behavioural profile per source IP.
    prof = defaultdict(lambda: {"events": 0, "failures": 0,
                                "event_types": set(), "hosts": defaultdict(int),
                                "versions": defaultdict(int)})
    for l in logs:
        p = prof[l.get("source_ip", "-")]
        p["events"] += 1
        if l.get("status") in ("failed", "blocked"):
            p["failures"] += 1
        p["event_types"].add(l.get("event", ""))
        p["hosts"][l.get("host", "-")] += 1
        v = l.get("version", "-")
        if v and v != "-":
            p["versions"][v] += 1

    ips = list(prof)
    if len(ips) < 3:               # too few entities for a meaningful baseline
        return []

    # 2. Three intuitive, independently-explainable features per IP.
    feats = {
        "failures":        {ip: prof[ip]["failures"]         for ip in ips},
        "events":          {ip: prof[ip]["events"]           for ip in ips},
        "distinct_events": {ip: len(prof[ip]["event_types"]) for ip in ips},
    }
    labels = {"failures": "failed/blocked events",
              "events": "total event volume",
              "distinct_events": "distinct action types"}

    # 3. Robust baseline per feature: median + MAD modified z-scores.
    scores = {f: _robust_z(vals) for f, vals in feats.items()}   # f -> ({ip:z}, median)

    # 4. Flag any IP whose worst feature sits > z_threshold above normal.
    findings = []
    for ip in ips:
        z, feat = max(((scores[f][0][ip], f) for f in feats), key=lambda zf: zf[0])
        if z < z_threshold:
            continue
        median = scores[feat][1]
        top_host = max(prof[ip]["hosts"], key=prof[ip]["hosts"].get)
        versions = prof[ip]["versions"]
        findings.append({
            "type": "Behavioral Anomaly", "ip": ip, "host": top_host,
            "count": feats[feat][ip],
            "version": max(versions, key=versions.get) if versions else "-",
            "breached": z >= 2 * z_threshold,
            "severity": "HIGH" if z >= 2 * z_threshold else "MEDIUM",
            "reason": (f'{labels[feat]} = {feats[feat][ip]} vs network median '
                       f'{median:.1f} ({z:.1f}σ above normal, robust median/MAD)'),
        })
    return findings

# ---------------------------------------------------------------- CVE correlation
def correlate(finding, cves):
    v = finding.get("version", "-")
    return [c for c in cves if v in c.get("affected_versions", [])]

# ---------------------------------------------------------------- alerts
def _sev_rank(s):
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(s, 3)

def build_alert(finding, matched):
    base_sev = finding.get("severity") or ("HIGH" if finding["breached"] else "MEDIUM")
    if matched:
        top = max(matched, key=lambda c: c["cvss"])
        # a CVE match can RAISE severity but never lowers a detector's own rating
        sev = base_sev if _sev_rank(base_sev) <= _sev_rank(top["severity"]) else top["severity"]
        cve_line = (f' \u2014 matches {top["id"]} (CVSS {top["cvss"]}). '
                    f'{top["recommended_action"]}')
    else:
        sev = base_sev
        cve_line = " \u2014 no matching CVE in cache."
    body = finding.get("reason") or (
        f'{finding["count"]} events; affected software {finding["version"]}')
    return {
        "severity": sev,
        "method": finding.get("method", "signature"),
        "title": f'{finding["type"]} on {finding["host"]} from {finding["ip"]}',
        "detail": f'{body}{cve_line}',
        "cves": [c["id"] for c in matched],
    }

def evaluate(logs, cves):
    findings = []
    for f in detect_brute_force(logs) + detect_port_scan(logs):
        f["method"] = "signature"        # known attack shapes -> precise label
        findings.append(f)
    for f in detect_statistical_anomalies(logs):
        f["method"] = "behavioral"       # the generalizer -> catches the unknown
        findings.append(f)
    alerts = [build_alert(f, correlate(f, cves)) for f in findings]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: order.get(a["severity"], 3))
    return alerts

if __name__ == "__main__":
    # Windows consoles default to cp1252, which can't encode chars like 'σ' or
    # '—'. Force UTF-8 so output is correct everywhere (and never crashes).
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default=DEFAULT_LOGS)
    ap.add_argument("--cve", default=DEFAULT_CVE)
    a = ap.parse_args()
    alerts = evaluate(load(a.logs), load(a.cve))
    print(f"\n=== {len(alerts)} ALERT(S) ===\n")
    for al in alerts:
        print(f'[{al["severity"]}] ({al["method"]}) {al["title"]}')
        print(f'   {al["detail"]}\n')
