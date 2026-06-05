"""
APP 1 - LOG GENERATOR
Produces realistic multi-source logs with configurable normal vs attack mix.
Exports JSON / CSV / syslog.

KEY TRICK: the attack burst uses a software version (OpenSSH 7.2p2) that we KNOW
is in App 2's CVE cache -> guarantees a clean correlation in the demo.

Run:  python generator.py --lines 50000 --attacks brute_force --out ../data/logs.json
"""
import json, csv, random, argparse
from datetime import datetime, timedelta

NORMAL_IPS = [f"10.0.0.{i}" for i in range(2, 60)]
ATTACKER_IP = "185.220.101.47"        # single hostile IP for the brute-force burst
HOSTS = ["web-01", "web-02", "db-01", "auth-01"]
SERVICES = ["sshd", "nginx", "postgres", "firewall"]
VULN_VERSION = "OpenSSH_7.2p2"        # <-- matches CVE cache in App 2

def ts(base, secs):
    return (base + timedelta(seconds=secs)).isoformat()

def normal_entry(base, sec):
    return {
        "timestamp": ts(base, sec),
        "source_ip": random.choice(NORMAL_IPS),
        "host": random.choice(HOSTS),
        "service": random.choice(SERVICES),
        "version": VULN_VERSION if random.random() < 0.3 else "nginx/1.18.0",
        "event": "connection",
        "status": "success",
    }

def brute_force_burst(base, start_sec, n=200):
    """n failed SSH logins from one IP, then ONE success = classic brute-force."""
    out = []
    for i in range(n):
        out.append({
            "timestamp": ts(base, start_sec + i),
            "source_ip": ATTACKER_IP, "host": "web-01", "service": "sshd",
            "version": VULN_VERSION, "event": "auth", "status": "failed",
        })
    out.append({
        "timestamp": ts(base, start_sec + n),
        "source_ip": ATTACKER_IP, "host": "web-01", "service": "sshd",
        "version": VULN_VERSION, "event": "auth", "status": "success",
    })
    return out

def port_scan_burst(base, start_sec):
    out = []
    for p in [21, 22, 23, 25, 80, 443, 3306, 5432, 8080]:
        out.append({
            "timestamp": ts(base, start_sec), "source_ip": ATTACKER_IP,
            "host": "firewall", "service": "firewall", "version": "-",
            "event": f"port_probe:{p}", "status": "blocked",
        })
    return out

def generate(lines, attacks):
    base = datetime(2026, 6, 5, 9, 0, 0)
    logs = [normal_entry(base, s) for s in range(lines)]
    if "brute_force" in attacks:
        logs += brute_force_burst(base, start_sec=lines // 2)
    if "port_scan" in attacks:
        logs += port_scan_burst(base, start_sec=lines // 3)
    logs.sort(key=lambda x: x["timestamp"])
    return logs

def export(logs, path):
    if path.endswith(".json"):
        json.dump(logs, open(path, "w"), indent=2)
    elif path.endswith(".csv"):
        w = csv.DictWriter(open(path, "w", newline=""), fieldnames=logs[0].keys())
        w.writeheader(); w.writerows(logs)
    else:  # syslog-ish
        with open(path, "w") as f:
            for l in logs:
                f.write(f'{l["timestamp"]} {l["host"]} {l["service"]}[{l["version"]}]: '
                        f'{l["event"]} {l["status"]} from {l["source_ip"]}\n')

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=5000)
    ap.add_argument("--attacks", default="brute_force,port_scan")
    ap.add_argument("--out", default="../data/logs.json")
    a = ap.parse_args()
    logs = generate(a.lines, a.attacks.split(","))
    export(logs, a.out)
    print(f"Generated {len(logs)} log lines -> {a.out}")
    print(f"Injected attacks: {a.attacks}")
