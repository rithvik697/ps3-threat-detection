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
SQLI_THRESHOLD = 5            # SQL-injection attempts from one IP -> campaign
PORT_SCAN_THRESHOLD = 5       # PORT_SCAN events from one IP -> active scanner
DISTRIBUTED_THRESHOLD = 50    # total events of a labelled attack -> aggregate incident
ANOMALY_MIN_EVENTS = 5        # only profile IPs with >= this many events (kills one-off flood)
ANOMALY_Z_THRESHOLD = 3.5     # modified z-score (median/MAD) cutoff for an outlier

# --- INPUT SCHEMA VOCABULARY ------------------------------------------------
# The exact string values the generator emits (verified against App 1's output).
ST_AUTH = "AUTH"
ST_FIREWALL = "FIREWALL"
ST_WEB = "WEB"
ST_NETWORK = "NETWORK"
ET_LOGIN_FAILED = "LOGIN_FAILED"
ET_LOGIN_SUCCESS = "LOGIN_SUCCESS"
ET_SQL_INJECTION = "SQL_INJECTION"
ET_PORT_SCAN = "PORT_SCAN"
ET_BLOCKED_CONNECTION = "BLOCKED_CONNECTION"     # firewall drop
# event_types that count as a failure/anomaly signal for the behavioral layer
FAILURE_EVENT_TYPES = {ET_LOGIN_FAILED, ET_BLOCKED_CONNECTION,
                       ET_SQL_INJECTION, ET_PORT_SCAN}

# --- CVE correlation --------------------------------------------------------
# destination_port -> software family, so we correlate CVEs without needing a
# version field in the logs. Aligned with App 1's asset inventory.
PORT_SOFTWARE = {22: "OpenSSH", 80: "nginx", 443: "nginx",
                 3306: "MySQL", 5432: "PostgreSQL", 8080: "Apache Tomcat",
                 161: "NetworkMonitor"}

# --- default data paths (anchored to <project_root>/data) -------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOGS = os.path.join(PROJECT_ROOT, "data", "logs.json")
DEFAULT_CVE = os.path.join(PROJECT_ROOT, "data", "cve_cache.json")
