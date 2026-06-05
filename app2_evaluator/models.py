"""
Output contract shared with the frontend/UI.

A detector produces one SecurityIncident per detected threat. `evidence` is an
open dict carrying the explainability detail (method, reason, matched CVE,
severity), so the schema stays stable while detail can grow.
"""
from dataclasses import dataclass, field


@dataclass
class SecurityIncident:
    attack_type: str
    target_host: str
    target_port: int
    source_ips: list
    confidence: float
    evidence: dict = field(default_factory=dict)
