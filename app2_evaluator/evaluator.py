"""
APP 2 - LOG EVALUATOR
Reads security events (new schema), detects attacks with two layers
(signature rules + a signature-free behavioral/statistical layer), correlates
the targeted service to cached CVEs, and emits structured SecurityIncident
objects.

Run:  python evaluator.py --logs ../data/logs.json --cve ../data/cve_cache.json
      python evaluator.py --json        # machine-readable output for the UI
"""
import json, argparse, os, sys
from collections import defaultdict
from dataclasses import dataclass, asdict, field

# ----------------------------------------------------------------- thresholds
FAILED_LOGIN_THRESHOLD = 50   # failed logins from one IP/host -> brute-force
PORT_SCAN_THRESHOLD = 5       # distinct ports from one IP -> port scan
ANOMALY_Z_THRESHOLD = 3.5     # modified z-score (median/MAD) cutoff for an outlier

# ----------------------------------------------------------------- INPUT SCHEMA VOCAB
# These are the exact string values the generator emits. If the generator team
# uses different names, change them HERE — the detection logic doesn't change.
ST_AUTH = "AUTH"
ST_FIREWALL = "FIREWALL"
ST_WEB = "WEB"
ET_LOGIN_FAILED = "LOGIN_FAILED"
ET_LOGIN_SUCCESS = "LOGIN_SUCCESS"
ET_CONN_BLOCKED = "CONNECTION_BLOCKED"          # firewall drop (used for port scan)
FAILURE_EVENT_TYPES = {ET_LOGIN_FAILED, ET_CONN_BLOCKED}

# destination_port -> software family, so we can correlate CVEs without a
# version field in the logs. Extend as needed.
PORT_SOFTWARE = {22: "OpenSSH", 80: "nginx", 443: "nginx",
                 3306: "MySQL", 5432: "PostgreSQL"}

# Anchor defaults to <project_root>/data so the script works from any directory.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOGS = os.path.join(PROJECT_ROOT, "data", "logs.json")
DEFAULT_CVE = os.path.join(PROJECT_ROOT, "data", "cve_cache.json")


# ----------------------------------------------------------------- OUTPUT CONTRACT
@dataclass
class SecurityIncident:
    attack_type: str
    target_host: str
    target_port: int
    source_ips: list
    confidence: float
    evidence: dict = field(default_factory=dict)


def load(path):
    return json.load(open(path))


# ----------------------------------------------------------------- robust stats
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

def _is_http_error(code):
    return isinstance(code, int) and code >= 400


# ----------------------------------------------------------------- detection (signatures)
def detect_brute_force(logs):
    """Many failed logins from one IP against one host (optionally followed by
    a success = a confirmed breach)."""
    fails = defaultdict(list)
    successes = set()
    for l in logs:
        if l.get("source_type") == ST_AUTH and l.get("event_type") == ET_LOGIN_FAILED:
            fails[(l.get("source_ip"), l.get("host"))].append(l)
        elif l.get("source_type") == ST_AUTH and l.get("event_type") == ET_LOGIN_SUCCESS:
            successes.add((l.get("source_ip"), l.get("host")))
    findings = []
    for (ip, host), entries in fails.items():
        if len(entries) >= FAILED_LOGIN_THRESHOLD:
            breached = (ip, host) in successes
            port = entries[0].get("destination_port") or 0
            findings.append({
                "attack_type": "Brute Force" + (" (successful)" if breached else ""),
                "target_host": host, "target_port": port, "source_ips": [ip],
                "count": len(entries), "breached": breached,
                "confidence": 0.97 if breached else 0.85,
                "reason": (f'{len(entries)} failed logins from {ip} on {host}'
                           + (' followed by a successful login' if breached else '')),
            })
    return findings

def detect_port_scan(logs, min_ports=PORT_SCAN_THRESHOLD):
    """One IP touching many distinct destination ports = reconnaissance."""
    ports_by_ip = defaultdict(set)
    hosts_by_ip = defaultdict(lambda: defaultdict(int))
    for l in logs:
        if l.get("source_type") == ST_FIREWALL or l.get("event_type") == ET_CONN_BLOCKED:
            dp = l.get("destination_port")
            if dp is not None:
                ip = l.get("source_ip")
                ports_by_ip[ip].add(dp)
                hosts_by_ip[ip][l.get("host", "-")] += 1
    findings = []
    for ip, ports in ports_by_ip.items():
        if len(ports) >= min_ports:
            host = max(hosts_by_ip[ip], key=hosts_by_ip[ip].get)
            findings.append({
                "attack_type": "Port Scan",
                "target_host": host, "target_port": 0, "source_ips": [ip],
                "count": len(ports), "breached": False, "confidence": 0.8,
                "reason": f'{ip} probed {len(ports)} distinct ports: {sorted(ports)}',
            })
    return findings


# ----------------------------------------------------------------- detection (generalizer)
def detect_statistical_anomalies(logs, z_threshold=ANOMALY_Z_THRESHOLD):
    """Signature-FREE detection: the generalizer.

    Instead of looking for KNOWN attack shapes, profile how every source IP
    behaves, build a population baseline of 'normal', and flag any IP that
    deviates sharply. Catches novel attacks we never wrote a rule for (e.g.
    password spraying that stays under the per-host brute-force threshold).
    No training, no labels, fully explainable.
    """
    prof = defaultdict(lambda: {"events": 0, "failures": 0, "ports": set(),
                                "hosts": defaultdict(int), "port_counts": defaultdict(int)})
    for l in logs:
        p = prof[l.get("source_ip", "-")]
        p["events"] += 1
        if l.get("event_type") in FAILURE_EVENT_TYPES or _is_http_error(l.get("status_code")):
            p["failures"] += 1
        dp = l.get("destination_port")
        if dp is not None:
            p["ports"].add(dp)
            p["port_counts"][dp] += 1
        p["hosts"][l.get("host", "-")] += 1

    ips = list(prof)
    if len(ips) < 3:               # too few entities for a meaningful baseline
        return []

    # Three intuitive, independently-explainable behavioural features per IP.
    feats = {
        "failures":       {ip: prof[ip]["failures"]   for ip in ips},
        "events":         {ip: prof[ip]["events"]     for ip in ips},
        "distinct_ports": {ip: len(prof[ip]["ports"]) for ip in ips},
    }
    labels = {"failures": "failed/blocked events",
              "events": "total event volume",
              "distinct_ports": "distinct ports touched"}

    scores = {f: _robust_z(vals) for f, vals in feats.items()}   # f -> ({ip:z}, median)

    findings = []
    for ip in ips:
        z, feat = max(((scores[f][0][ip], f) for f in feats), key=lambda zf: zf[0])
        if z < z_threshold:
            continue
        median = scores[feat][1]
        host = max(prof[ip]["hosts"], key=prof[ip]["hosts"].get)
        pc = prof[ip]["port_counts"]
        port = max(pc, key=pc.get) if pc else 0
        findings.append({
            "attack_type": "Behavioral Anomaly",
            "target_host": host, "target_port": port, "source_ips": [ip],
            "count": feats[feat][ip], "breached": z >= 2 * z_threshold,
            "severity": "HIGH" if z >= 2 * z_threshold else "MEDIUM",
            "confidence": round(min(0.99, z / (z + z_threshold)), 2),
            "reason": (f'{labels[feat]} = {feats[feat][ip]} vs network median '
                       f'{median:.1f} ({z:.1f}σ above normal, robust median/MAD)'),
        })
    return findings


# ----------------------------------------------------------------- CVE correlation
def _sev_rank(s):
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(s, 3)

def correlate(target_port, cves):
    """Map the targeted port -> software family -> known CVEs for that service.
    Returns (software_name_or_None, [matching cve dicts])."""
    software = PORT_SOFTWARE.get(target_port)
    if not software:
        return None, []
    matches = [c for c in cves if c.get("software", "").lower() == software.lower()]
    return software, matches


# ----------------------------------------------------------------- incident assembly
def build_incident(finding, cves):
    port = finding.get("target_port") or 0
    software, matched = correlate(port, cves)
    severity = finding.get("severity") or ("HIGH" if finding.get("breached") else "MEDIUM")

    evidence = {
        "method": finding.get("method", "signature"),
        "event_count": finding.get("count"),
        "reason": finding.get("reason") or finding["attack_type"],
    }
    if software:
        evidence["affected_software"] = software
    if matched:
        top = max(matched, key=lambda c: c["cvss"])
        # a CVE match can RAISE severity but never lowers a detector's own rating
        if _sev_rank(top["severity"]) < _sev_rank(severity):
            severity = top["severity"]
        evidence["matched_cves"] = [c["id"] for c in matched]
        evidence["top_cve"] = top["id"]
        evidence["cvss"] = top["cvss"]
        evidence["recommended_action"] = top["recommended_action"]
    evidence["severity"] = severity

    return SecurityIncident(
        attack_type=finding["attack_type"],
        target_host=finding.get("target_host", "-"),
        target_port=port,
        source_ips=finding.get("source_ips", []),
        confidence=finding.get("confidence", 0.8),
        evidence=evidence,
    )

def evaluate(logs, cves):
    findings = []
    for f in detect_brute_force(logs) + detect_port_scan(logs):
        f.setdefault("method", "signature")   # known attack shapes -> precise label
        findings.append(f)
    for f in detect_statistical_anomalies(logs):
        f.setdefault("method", "behavioral")  # the generalizer -> catches the unknown
        findings.append(f)
    incidents = [build_incident(f, cves) for f in findings]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    incidents.sort(key=lambda i: (order.get(i.evidence.get("severity"), 3), -i.confidence))
    return incidents


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
    ap.add_argument("--json", action="store_true", help="emit incidents as JSON")
    a = ap.parse_args()

    incidents = evaluate(load(a.logs), load(a.cve))

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
                print(f'   → {ev["top_cve"]} (CVSS {ev["cvss"]}) — {ev["recommended_action"]}')
            print()
