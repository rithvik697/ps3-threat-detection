# --------------------------------
# ASSET INVENTORY GENERATION
# --------------------------------

assets = []

all_hosts = []

for host_list in HOSTS.values():
    all_hosts.extend(host_list)

for host in all_hosts:

    if host.startswith("web"):

        assets.append({
            "host": host,
            "criticality": "HIGH",
            "services": [
                {
                    "name": "OpenSSH",
                    "version": "8.4",
                    "port": 22
                },
                {
                    "name": "Nginx",
                    "version": "1.20",
                    "port": 443
                }
            ]
        })

    elif host.startswith("auth"):

        assets.append({
            "host": host,
            "criticality": "CRITICAL",
            "services": [
                {
                    "name": "OpenSSH",
                    "version": "7.2",
                    "port": 22
                }
            ]
        })

    elif host.startswith("app"):

        assets.append({
            "host": host,
            "criticality": "HIGH",
            "services": [
                {
                    "name": "Tomcat",
                    "version": "9.0",
                    "port": 8080
                }
            ]
        })

    elif host.startswith("fw"):

        assets.append({
            "host": host,
            "criticality": "CRITICAL",
            "services": [
                {
                    "name": "FirewallD",
                    "version": "1.0",
                    "port": 0
                }
            ]
        })

    elif host.startswith("net"):

        assets.append({
            "host": host,
            "criticality": "MEDIUM",
            "services": [
                {
                    "name": "NetworkMonitor",
                    "version": "2.1",
                    "port": 161
                }
            ]
        })

# Export assets

with open("assets.json", "w") as f:
    json.dump(
        assets,
        f,
        indent=4
    )

print("assets.json generated successfully.")