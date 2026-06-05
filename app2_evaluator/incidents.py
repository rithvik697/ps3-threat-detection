"""
Incident assembly + the evaluation pipeline  (owner: E3).

Turns raw detector findings into SecurityIncident objects (attaching CVE
correlation and final severity), then runs the whole pipeline and prioritises
the results.
"""
from models import SecurityIncident
from correlation import sev_rank, correlate
from detectors import detect_all


def build_incident(finding, cves, use_live=False):
    port = finding.get("target_port") or 0
    software, matched, source = correlate(port, cves, use_live)
    severity = finding.get("severity") or ("HIGH" if finding.get("breached") else "MEDIUM")

    evidence = {
        "method": finding.get("method", "signature"),
        "event_count": finding.get("count"),
        "reason": finding.get("reason") or finding["attack_type"],
    }
    evidence.update(finding.get("extra", {}))     # detector-specific detail
    if software:
        evidence["affected_software"] = software
    if matched:
        top = matched[0]                          # resolve_cves returns best-first
        # a CVE match can RAISE severity but never lowers a detector's own rating
        if sev_rank(top["severity"]) < sev_rank(severity):
            severity = top["severity"]
        evidence["matched_cves"] = [c["id"] for c in matched][:10]
        evidence["top_cve"] = top["id"]
        evidence["cvss"] = top["cvss"]
        evidence["recommended_action"] = top["recommended_action"]
        evidence["cve_source"] = source          # 'NVD (live)' or 'cache' -> freshness
    evidence["severity"] = severity

    return SecurityIncident(
        attack_type=finding["attack_type"],
        target_host=finding.get("target_host", "-"),
        target_port=port,
        source_ips=finding.get("source_ips", []),
        confidence=finding.get("confidence", 0.8),
        evidence=evidence,
    )


def correlate_findings(findings, cves, use_live=False):
    """PHASE 2 — CORRELATION: attach CVE matches + final severity to each
    finding, producing SecurityIncident objects. With use_live, pulls the
    latest CVEs from NVD (cache fallback)."""
    return [build_incident(f, cves, use_live) for f in findings]


def prioritise(incidents):
    """PHASE 3 — order by severity, then by confidence within a severity."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(incidents,
                  key=lambda i: (order.get(i.evidence.get("severity"), 4), -i.confidence))


def evaluate(logs, cves, use_live=False):
    """Full pipeline, run as distinct phases — one after the other."""
    findings = detect_all(logs)                                  # 1. detect every attack
    incidents = correlate_findings(findings, cves, use_live)     # 2. then correlate with CVEs
    return prioritise(incidents)                                 # 3. then prioritise
