"""
Detection layer  (owner: E1).

Two kinds of detector:
  * signature rules  -> known attack shapes, precise labels
  * the generalizer  -> signature-free statistical anomaly detection

Each detector returns plain 'finding' dicts. Turning findings into
SecurityIncident objects (and CVE correlation) happens in incidents.py, so
detection stays independent of output formatting.
"""
from collections import defaultdict

import config
from stats import robust_z, is_http_error


# ----------------------------------------------------------------- signatures
def detect_brute_force(logs):
    """Many failed logins from one IP against one host (optionally followed by
    a success = a confirmed breach)."""
    fails = defaultdict(list)
    successes = set()
    for l in logs:
        if l.get("source_type") == config.ST_AUTH and l.get("event_type") == config.ET_LOGIN_FAILED:
            fails[(l.get("source_ip"), l.get("host"))].append(l)
        elif l.get("source_type") == config.ST_AUTH and l.get("event_type") == config.ET_LOGIN_SUCCESS:
            successes.add((l.get("source_ip"), l.get("host")))
    findings = []
    for (ip, host), entries in fails.items():
        if len(entries) >= config.FAILED_LOGIN_THRESHOLD:
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


def detect_port_scan(logs, min_ports=config.PORT_SCAN_THRESHOLD):
    """One IP touching many distinct destination ports = reconnaissance."""
    ports_by_ip = defaultdict(set)
    hosts_by_ip = defaultdict(lambda: defaultdict(int))
    for l in logs:
        if l.get("source_type") == config.ST_FIREWALL or l.get("event_type") == config.ET_CONN_BLOCKED:
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


# ----------------------------------------------------------------- generalizer
def detect_statistical_anomalies(logs, z_threshold=config.ANOMALY_Z_THRESHOLD):
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
        if l.get("event_type") in config.FAILURE_EVENT_TYPES or is_http_error(l.get("status_code")):
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

    scores = {f: robust_z(vals) for f, vals in feats.items()}   # f -> ({ip:z}, median)

    findings = []
    for ip in ips:
        z, feat = max(((scores[f][0][ip], f) for f in feats), key=lambda zf: zf[0])
        if z < z_threshold:
            continue
        med = scores[feat][1]
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
                       f'{med:.1f} ({z:.1f}σ above normal, robust median/MAD)'),
        })
    return findings


# ----------------------------------------------------------------- phase 1 entry
def detect_all(logs):
    """PHASE 1 — DETECTION (no CVE knowledge here).

    Run every detector and return a flat list of findings, each tagged with the
    method that produced it. Correlation happens afterwards as a separate phase.
    """
    findings = []
    for f in detect_brute_force(logs) + detect_port_scan(logs):
        f.setdefault("method", "signature")   # known attack shapes -> precise label
        findings.append(f)
    for f in detect_statistical_anomalies(logs):
        f.setdefault("method", "behavioral")  # the generalizer -> catches the unknown
        findings.append(f)
    return findings
