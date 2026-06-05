"""
APP 1 - MULTI-SOURCE CYBER LOG GENERATOR

Generates synthetic security telemetry that matches App 2's evaluator schema.

Examples:
    python generator.py
    python generator.py --lines 50000 --attacks brute_force,port_scan --out logs.json
    python generator.py --lines 50000 --attacks brute_force,port_scan --out ../data/logs.json
"""
import argparse
import csv
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path


HOSTS = {
    "web": ["web-01", "web-02"],
    "auth": ["auth-01", "auth-02"],
    "app": ["app-01", "app-02"],
    "firewall": ["fw-01"],
    "network": ["net-01"],
}

ASSET_PROFILES = {
    "web": {
        "criticality": "HIGH",
        "services": [
            {"name": "OpenSSH", "version": "8.4", "port": 22},
            {"name": "Nginx", "version": "1.20", "port": 443},
        ],
    },
    "auth": {
        "criticality": "CRITICAL",
        "services": [{"name": "OpenSSH", "version": "7.2", "port": 22}],
    },
    "app": {
        "criticality": "HIGH",
        "services": [{"name": "Tomcat", "version": "9.0", "port": 8080}],
    },
    "fw": {
        "criticality": "CRITICAL",
        "services": [{"name": "FirewallD", "version": "1.0", "port": 0}],
    },
    "net": {
        "criticality": "MEDIUM",
        "services": [{"name": "NetworkMonitor", "version": "2.1", "port": 161}],
    },
}

FIELDNAMES = [
    "event_id",
    "timestamp",
    "host",
    "source_type",
    "event_type",
    "severity",
    "source_ip",
    "destination_ip",
    "destination_port",
    "request_method",
    "status_code",
    "payload",
    "session_id",
]

NORMAL_TEMPLATES = [
    {
        "source_type": "AUTH",
        "event_type": "LOGIN_SUCCESS",
        "severity": "LOW",
        "hosts": HOSTS["auth"],
        "ports": [22],
        "methods": [None],
        "status_codes": [200],
        "payloads": ["interactive login", "service account login", "ssh key accepted"],
    },
    {
        "source_type": "WEB",
        "event_type": "PAGE_VISIT",
        "severity": "LOW",
        "hosts": HOSTS["web"],
        "ports": [80, 443],
        "methods": ["GET", "POST"],
        "status_codes": [200, 200, 201, 204, 301, 302],
        "payloads": ["/", "/login", "/dashboard", "/api/health", "/static/app.js"],
    },
    {
        "source_type": "APPLICATION",
        "event_type": "API_REQUEST",
        "severity": "LOW",
        "hosts": HOSTS["app"],
        "ports": [8080],
        "methods": ["GET", "POST", "PUT"],
        "status_codes": [200, 201, 204],
        "payloads": ["orders lookup", "profile update", "inventory query"],
    },
    {
        "source_type": "APPLICATION",
        "event_type": "USER_UPDATE",
        "severity": "LOW",
        "hosts": HOSTS["app"],
        "ports": [8080],
        "methods": ["POST", "PATCH"],
        "status_codes": [200, 204],
        "payloads": ["role unchanged", "preferences saved", "metadata updated"],
    },
    {
        "source_type": "FIREWALL",
        "event_type": "ALLOWED_CONNECTION",
        "severity": "LOW",
        "hosts": HOSTS["firewall"],
        "ports": [80, 443, 22, 8080],
        "methods": [None],
        "status_codes": [200],
        "payloads": ["stateful allow", "known route", "policy allow"],
    },
    {
        "source_type": "NETWORK",
        "event_type": "NORMAL_TRAFFIC",
        "severity": "LOW",
        "hosts": HOSTS["network"],
        "ports": [53, 123, 161, 443],
        "methods": [None],
        "status_codes": [200],
        "payloads": ["dns query", "ntp sync", "snmp poll", "tls session"],
    },
]

ATTACK_IPS = {
    "brute_force": "203.0.113.77",
    "port_scan": "198.51.100.23",
    "sql_injection": "185.220.101.47",
}


def parse_attacks(value):
    if not value or value.lower() in {"none", "clean"}:
        return set()
    return {part.strip().lower() for part in value.split(",") if part.strip()}


def host_group(host):
    if host.startswith("web"):
        return "web"
    if host.startswith("auth"):
        return "auth"
    if host.startswith("app"):
        return "app"
    if host.startswith("fw"):
        return "fw"
    if host.startswith("net"):
        return "net"
    return "web"


def build_assets():
    assets = []
    for host_list in HOSTS.values():
        for host in host_list:
            profile = ASSET_PROFILES[host_group(host)]
            assets.append({
                "host": host,
                "criticality": profile["criticality"],
                "services": profile["services"],
            })
    return assets


def destination_ip_for(host):
    octet = {
        "web-01": 10,
        "web-02": 11,
        "auth-01": 20,
        "auth-02": 21,
        "app-01": 30,
        "app-02": 31,
        "fw-01": 1,
        "net-01": 40,
    }.get(host, 254)
    return f"10.0.0.{octet}"


def new_event(rng, ts, template, source_ip=None, overrides=None):
    host = rng.choice(template["hosts"])
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "host": host,
        "source_type": template["source_type"],
        "event_type": template["event_type"],
        "severity": template["severity"],
        "source_ip": source_ip or f"10.0.1.{rng.randint(1, 220)}",
        "destination_ip": destination_ip_for(host),
        "destination_port": rng.choice(template["ports"]),
        "request_method": rng.choice(template["methods"]),
        "status_code": rng.choice(template["status_codes"]),
        "payload": rng.choice(template["payloads"]),
        "session_id": f"sess_{rng.randint(100000, 999999)}",
    }
    if overrides:
        event.update(overrides)
        if "host" in overrides and "destination_ip" not in overrides:
            event["destination_ip"] = destination_ip_for(event["host"])
    return event


def normal_event(rng, ts):
    return new_event(rng, ts, rng.choice(NORMAL_TEMPLATES))


def brute_force_events(rng, start_ts, lines):
    count = min(max(60, lines // 250), 250)
    events = []
    auth_template = NORMAL_TEMPLATES[0]
    ip = ATTACK_IPS["brute_force"]
    for i in range(count):
        events.append(new_event(
            rng,
            start_ts + timedelta(seconds=i),
            auth_template,
            source_ip=ip,
            overrides={
                "host": "auth-01",
                "event_type": "LOGIN_FAILED",
                "severity": "HIGH",
                "destination_port": 22,
                "status_code": 401,
                "payload": "invalid password",
            },
        ))
    events.append(new_event(
        rng,
        start_ts + timedelta(seconds=count),
        auth_template,
        source_ip=ip,
        overrides={
            "host": "auth-01",
            "event_type": "LOGIN_SUCCESS",
            "severity": "CRITICAL",
            "destination_port": 22,
            "status_code": 200,
            "payload": "successful login after repeated failures",
        },
    ))
    return events


def port_scan_events(rng, start_ts, lines):
    count = min(max(10, lines // 1000), 80)
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 5432, 8080]
    events = []
    network_template = NORMAL_TEMPLATES[5]
    ip = ATTACK_IPS["port_scan"]
    for i in range(count):
        port = ports[i % len(ports)]
        events.append(new_event(
            rng,
            start_ts + timedelta(seconds=i),
            network_template,
            source_ip=ip,
            overrides={
                "host": "net-01",
                "source_type": "NETWORK",
                "event_type": "PORT_SCAN",
                "severity": "HIGH",
                "destination_port": port,
                "status_code": None,
                "payload": f"Scanning port {port}",
            },
        ))
    return events


def sql_injection_events(rng, start_ts, lines):
    count = min(max(12, lines // 500), 200)
    payloads = ["' OR 1=1 --", "UNION SELECT password FROM users", "admin'--", "1; DROP TABLE users"]
    events = []
    web_template = NORMAL_TEMPLATES[1]
    ip = ATTACK_IPS["sql_injection"]
    for i in range(count):
        events.append(new_event(
            rng,
            start_ts + timedelta(seconds=i),
            web_template,
            source_ip=ip,
            overrides={
                "host": rng.choice(HOSTS["web"]),
                "source_type": "WEB",
                "event_type": "SQL_INJECTION",
                "severity": "CRITICAL",
                "destination_port": 3306,
                "request_method": "POST",
                "status_code": 403,
                "payload": rng.choice(payloads),
            },
        ))
    return events


def generate_logs(lines, attacks, seed=None):
    rng = random.Random(seed)
    base_ts = datetime.now().replace(microsecond=0)
    logs = []

    attack_builders = {
        "brute_force": brute_force_events,
        "port_scan": port_scan_events,
        "sql_injection": sql_injection_events,
    }

    for index, attack in enumerate(sorted(attacks)):
        builder = attack_builders.get(attack)
        if builder:
            logs.extend(builder(rng, base_ts + timedelta(minutes=index * 5), lines))

    remaining = max(0, lines - len(logs))
    for i in range(remaining):
        logs.append(normal_event(rng, base_ts + timedelta(seconds=i)))

    logs = logs[:lines]
    logs.sort(key=lambda event: event["timestamp"])
    return logs


def write_json(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2)


def write_csv(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)


def write_syslog(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in records:
            handle.write(
                f"{event['timestamp']} {event['host']} "
                f"{event['source_type']}[{event['event_type']}]: "
                f"src={event['source_ip']} dst={event['destination_ip']} "
                f"port={event['destination_port']} severity={event['severity']} "
                f"payload={event['payload']}\n"
            )


def output_paths(out_path):
    stem = out_path.with_suffix("")
    return {
        "json": out_path,
        "csv": stem.with_suffix(".csv"),
        "syslog": stem.with_suffix(".syslog"),
        "assets": out_path.parent / "assets.json",
    }


def main():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Generate synthetic cyber logs.")
    parser.add_argument("--lines", type=int, default=50000, help="number of events to emit")
    parser.add_argument(
        "--attacks",
        default="brute_force,port_scan,sql_injection",
        help="comma-separated attacks: brute_force, port_scan, sql_injection, none",
    )
    parser.add_argument("--out", default=str(script_dir / "logs.json"), help="JSON output path")
    parser.add_argument("--seed", type=int, default=1337, help="random seed for repeatable demos")
    args = parser.parse_args()

    if args.lines < 1:
        raise SystemExit("--lines must be at least 1")

    out_path = Path(args.out).expanduser()
    if not out_path.is_absolute():
        out_path = Path.cwd() / out_path

    attacks = parse_attacks(args.attacks)
    logs = generate_logs(args.lines, attacks, seed=args.seed)
    paths = output_paths(out_path)

    write_json(paths["json"], logs)
    write_csv(paths["csv"], logs)
    write_syslog(paths["syslog"], logs)
    write_json(paths["assets"], build_assets())

    print(f"Generated {len(logs):,} logs -> {paths['json']}")
    print(f"Generated CSV -> {paths['csv']}")
    print(f"Generated syslog -> {paths['syslog']}")
    print(f"Generated assets -> {paths['assets']}")


if __name__ == "__main__":
    main()
