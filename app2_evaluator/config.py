"""
Shared configuration for the evaluator.

Everything the *generator team's choices* affect lives here: detection
thresholds, the exact input-schema vocabulary, and the port->software map for
CVE correlation. When the contract shifts, change a value HERE — never the
detection logic.
"""
import os

# --- detection thresholds ---------------------------------------------------
FAILED_LOGIN_THRESHOLD = 50   # failed logins from one IP/host -> brute-force
PORT_SCAN_THRESHOLD = 5       # distinct ports from one IP -> port scan
ANOMALY_Z_THRESHOLD = 3.5     # modified z-score (median/MAD) cutoff for an outlier

# --- INPUT SCHEMA VOCABULARY ------------------------------------------------
# The exact string values the generator emits. If the generator team uses
# different names, change them here and detection keeps working unchanged.
ST_AUTH = "AUTH"
ST_FIREWALL = "FIREWALL"
ST_WEB = "WEB"
ET_LOGIN_FAILED = "LOGIN_FAILED"
ET_LOGIN_SUCCESS = "LOGIN_SUCCESS"
ET_CONN_BLOCKED = "CONNECTION_BLOCKED"          # firewall drop (used for port scan)
FAILURE_EVENT_TYPES = {ET_LOGIN_FAILED, ET_CONN_BLOCKED}

# --- CVE correlation --------------------------------------------------------
# destination_port -> software family, so we correlate CVEs without needing a
# version field in the logs. Extend as needed.
PORT_SOFTWARE = {22: "OpenSSH", 80: "nginx", 443: "nginx",
                 3306: "MySQL", 5432: "PostgreSQL"}

# --- default data paths (anchored to <project_root>/data) -------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOGS = os.path.join(PROJECT_ROOT, "data", "logs.json")
DEFAULT_CVE = os.path.join(PROJECT_ROOT, "data", "cve_cache.json")
