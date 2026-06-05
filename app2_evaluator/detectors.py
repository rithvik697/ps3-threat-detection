"""
Detection layer  (owner: E1).

The generator pre-labels every event with an `event_type` (LOGIN_FAILED,
SQL_INJECTION, PORT_SCAN, BLOCKED_CONNECTION, ...). So detection has two parts:

  * signature/campaign rules -> recognise labelled malicious events and
        AGGREGATE them per attacker (one incident per campaign, not per event,
        so 3000 SQLi events become ONE clean incident).
  * the generalizer          -> signature-free statistical anomaly detection,
        for behaviour we never wrote a rule for.

Each detector returns plain 'finding' dicts; turning findings into
SecurityIncident objects (and CVE correlation) happens in incidents.py.
"""
import math
from collections import defaultdict, Counter

import config
from stats import robust_z, is_http_error


# ----------------------------------------------------------------- helpers
def _finding_from_events(label, ips, evs, base_sev, concentrated, service_port=None):
    """Build one finding that summarises a group of malicious events.

    service_port lets a detector pin CVE correlation to the service the attack
    actually targets (e.g. credential attacks -> SSH/22), or disable it with 0
    (e.g. a port scan is reconnaissance, not exploitation of one CVE)."""
    hosts = Counter(e.get("host") for e in evs)
    ports = Counter(e.get("destination_port") for e in evs if e.get("destination_port"))
    if service_port is not None:
        port = service_port
    else:
        # prefer the most common port that maps to a known service, so CVE
        # correlation lands on something meaningful rather than an arbitrary port.
        mapped = [p for p, _ in ports.most_common() if p in config.PORT_SOFTWARE]
        port = mapped[0] if mapped else (ports.most_common(1)[0][0] if ports else 0)
    n = len(evs)
    sev = "CRITICAL" if (concentrated and n >= 50 and base_sev == "HIGH") else base_sev
    sample = next((e.get("payload") for e in evs if e.get("payload")), None)
    reason = (f'{n} {label} event(s) from {len(ips)} source IP(s) '
              f'targeting {len(hosts)} host(s)'
              + (f'; sample payload: {sample!r}' if sample else ''))
    return {
        "attack_type": label + ("" if concentrated else " (distributed)"),
        "target_host": hosts.most_common(1)[0][0] if hosts else "-",
        "target_port": port,
        "source_ips": ips[:10],
        "count": n,
        "breached": concentrated,
        "severity": sev,
        "confidence": round(min(0.99, 0.7 + n / 5000), 2),
        "reason": reason,
        "extra": {"source_ip_count": len(ips),
                  "targeted_ports": sorted(p for p in ports)[:15]},
    }


def _campaign_findings(logs, event_type, label, per_ip_threshold, base_sev,
                       service_port=None):
    """Aggregate labelled malicious events into incidents.

    A single IP exceeding `per_ip_threshold` events -> a focused per-attacker
    incident. The scattered remainder, if large, -> one aggregate 'distributed'
    incident (so thousands of one-off events don't become thousands of alerts).
    """
    by_ip = defaultdict(list)
    for l in logs:
        if l.get("event_type") == event_type:
            by_ip[l.get("source_ip")].append(l)

    findings, concentrated = [], set()
    for ip, evs in by_ip.items():
        if len(evs) >= per_ip_threshold:
            concentrated.add(ip)
            findings.append(_finding_from_events(label, [ip], evs, base_sev, True, service_port))

    rest = [(ip, evs) for ip, evs in by_ip.items() if ip not in concentrated]
    rest_n = sum(len(e) for _, e in rest)
    if rest_n >= config.DISTRIBUTED_THRESHOLD:
        ips = [ip for ip, _ in rest]
        all_evs = [e for _, evs in rest for e in evs]
        findings.append(_finding_from_events(label, ips, all_evs, base_sev, False, service_port))
    return findings


def _source_profiles(logs):
    """Aggregate source-IP behavior once so statistical and ML detectors agree."""
    prof = defaultdict(lambda: {"events": 0, "failures": 0, "ports": set(),
                                "hosts": defaultdict(int), "port_counts": defaultdict(int),
                                "http_errors": 0, "login_failed": 0, "sql_injection": 0,
                                "port_scan": 0, "blocked": 0})
    for l in logs:
        p = prof[l.get("source_ip", "-")]
        event_type = l.get("event_type")
        p["events"] += 1
        if event_type in config.FAILURE_EVENT_TYPES or is_http_error(l.get("status_code")):
            p["failures"] += 1
        if is_http_error(l.get("status_code")):
            p["http_errors"] += 1
        if event_type == config.ET_LOGIN_FAILED:
            p["login_failed"] += 1
        elif event_type == config.ET_SQL_INJECTION:
            p["sql_injection"] += 1
        elif event_type == config.ET_PORT_SCAN:
            p["port_scan"] += 1
        elif event_type == config.ET_BLOCKED_CONNECTION:
            p["blocked"] += 1
        dp = l.get("destination_port")
        if dp is not None:
            p["ports"].add(dp)
            p["port_counts"][dp] += 1
        p["hosts"][l.get("host", "-")] += 1
    return prof


# ----------------------------------------------------------------- signatures
def detect_brute_force(logs):
    """Many failed logins from one IP against one host (optionally followed by
    a success = a confirmed breach). Fires on CONCENTRATED brute force."""
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


def detect_sql_injection(logs):
    """SQL-injection attempts (labelled SQL_INJECTION), aggregated per attacker."""
    return _campaign_findings(logs, config.ET_SQL_INJECTION, "SQL Injection",
                              config.SQLI_THRESHOLD, "HIGH")


def detect_port_scan(logs):
    """Port-scan activity (labelled PORT_SCAN), aggregated per scanner.
    Reconnaissance is not exploitation of one CVE -> service_port=0 (no CVE);
    the scanned ports are listed in the incident evidence instead."""
    return _campaign_findings(logs, config.ET_PORT_SCAN, "Port Scan",
                              config.PORT_SCAN_THRESHOLD, "MEDIUM", service_port=0)


def detect_failed_logins(logs):
    """Failed-login surge (labelled LOGIN_FAILED) beyond concentrated brute force.
    Credential attacks target the auth service -> correlate to SSH (port 22)."""
    return _campaign_findings(logs, config.ET_LOGIN_FAILED, "Failed Login",
                              config.FAILED_LOGIN_THRESHOLD, "MEDIUM", service_port=22)


# ----------------------------------------------------------------- generalizer
def detect_statistical_anomalies(logs, z_threshold=config.ANOMALY_Z_THRESHOLD,
                                 min_events=config.ANOMALY_MIN_EVENTS):
    """Signature-FREE detection: the generalizer.

    Profiles how each ACTIVE source IP behaves, builds a population baseline of
    'normal', and flags any IP that deviates sharply. Only IPs with >=
    `min_events` events are profiled — without that floor, the flood of one-off
    IPs (each with a single event) makes any tiny value look like a huge
    outlier. No training, no labels, fully explainable.
    """
    prof = _source_profiles(logs)

    # Only profile IPs with enough activity to have a meaningful behaviour.
    ips = [ip for ip in prof if prof[ip]["events"] >= min_events]
    if len(ips) < 3:               # too few entities for a meaningful baseline
        return []

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


# ----------------------------------------------------------------- optional ML
def _ml_features(profile):
    events = profile["events"] or 1
    return [
        math.log1p(profile["events"]),
        math.log1p(profile["failures"]),
        profile["failures"] / events,
        math.log1p(len(profile["ports"])),
        math.log1p(len(profile["hosts"])),
        math.log1p(profile["http_errors"]),
        math.log1p(profile["login_failed"]),
        math.log1p(profile["sql_injection"]),
        math.log1p(profile["port_scan"]),
        math.log1p(profile["blocked"]),
    ]


def _has_ml_security_signal(profile):
    events = profile["events"] or 1
    failure_ratio = profile["failures"] / events
    if profile["failures"] >= config.ML_ANOMALY_MIN_FAILURES:
        return True
    if failure_ratio >= config.ML_ANOMALY_MIN_FAILURE_RATIO:
        return True
    if len(profile["ports"]) >= config.ML_ANOMALY_MIN_DISTINCT_PORTS:
        return True
    return False


def detect_ml_anomalies(logs):
    """unsupervised ML detector using sklearn IsolationForest.

    This is deliberately dependency-safe: if scikit-learn is not installed,
    the evaluator still runs and simply skips this extra layer.
    """
    if not config.ML_ANOMALY_ENABLED:
        return []
    try:
        from sklearn.ensemble import IsolationForest
    except Exception:
        return []

    prof = _source_profiles(logs)
    ips = [ip for ip in prof if prof[ip]["events"] >= config.ANOMALY_MIN_EVENTS]
    if len(ips) < config.ML_ANOMALY_MIN_IPS:
        return []

    rows = [_ml_features(prof[ip]) for ip in ips]
    model = IsolationForest(
        contamination=config.ML_ANOMALY_CONTAMINATION,
        random_state=config.ML_ANOMALY_RANDOM_STATE,
    )
    predictions = model.fit_predict(rows)
    scores = model.decision_function(rows)  # lower means more anomalous

    anomalous = [(ip, score) for ip, pred, score in zip(ips, predictions, scores)
                 if pred == -1 and _has_ml_security_signal(prof[ip])]
    anomalous.sort(key=lambda item: item[1])

    findings = []
    total = max(1, len(anomalous))
    for rank, (ip, score) in enumerate(anomalous, start=1):
        p = prof[ip]
        host = max(p["hosts"], key=p["hosts"].get)
        pc = p["port_counts"]
        port = max(pc, key=pc.get) if pc else 0
        failure_ratio = p["failures"] / (p["events"] or 1)
        confidence = round(min(0.99, 0.65 + (total - rank + 1) / total * 0.25), 2)
        severity = "HIGH" if (
            p["failures"] >= config.FAILED_LOGIN_THRESHOLD
            or p["sql_injection"] >= config.SQLI_THRESHOLD
            or p["port_scan"] >= config.PORT_SCAN_THRESHOLD
        ) else "MEDIUM"
        findings.append({
            "attack_type": "ML Behavioral Anomaly",
            "target_host": host, "target_port": port, "source_ips": [ip],
            "count": p["events"], "breached": severity == "HIGH",
            "severity": severity,
            "confidence": confidence,
            "reason": (
                "IsolationForest flagged source behavior as anomalous "
                f"(score {score:.3f}); events={p['events']}, "
                f"failures={p['failures']}, failure_ratio={failure_ratio:.2f}, "
                f"distinct_ports={len(p['ports'])}, distinct_hosts={len(p['hosts'])}; "
                "passed security-signal gate"
            ),
            "extra": {"model": "sklearn IsolationForest",
                      "features": ["events", "failures", "failure_ratio",
                                   "distinct_ports", "distinct_hosts", "http_errors",
                                   "login_failed", "sql_injection", "port_scan", "blocked"]},
        })
    return findings


# ----------------------------------------------------------------- phase 1 entry
SIGNATURE_DETECTORS = (detect_brute_force, detect_sql_injection,
                       detect_port_scan, detect_failed_logins)


def detect_all(logs):
    """PHASE 1 — DETECTION (no CVE knowledge here).

    Run every detector and return a flat list of findings, each tagged with the
    method that produced it. Correlation happens afterwards as a separate phase.
    """
    findings = []
    for detector in SIGNATURE_DETECTORS:
        for f in detector(logs):
            f.setdefault("method", "signature")   # labelled attack -> precise incident
            findings.append(f)
    for f in detect_statistical_anomalies(logs):
        f.setdefault("method", "behavioral")      # the generalizer -> catches the unknown
        findings.append(f)
    for f in detect_ml_anomalies(logs):
        f.setdefault("method", "ml")              # optional sklearn IsolationForest layer
        findings.append(f)
    return findings
