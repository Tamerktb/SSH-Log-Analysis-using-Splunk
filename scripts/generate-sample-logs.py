"""
SSH Log Generator

Generates realistic sample SSH authentication logs for testing
Splunk detection rules and dashboards without needing real infrastructure.

Usage:
    python generate-sample-logs.py

Output:
    ./output/auth.log    — Generated SSH auth log with attack patterns
    ./output/secure.log  — Alternative format for RHEL/CentOS systems
"""
import os
import random
import datetime

OUTPUT_DIR = "output"
TIMESTAMP_FORMAT = "%b %d %H:%M:%S"

USERS = ["root", "admin", "jdoe", "asmith", "devops", "oracle", "svc_backup", "deploy", "test_user", "ansible", "nagios", "docker", "guest"]
HOSTS = ["web-01", "web-02", "app-01", "db-01", "cache-01", "worker-01", "bastion-01"]

LEGITIMATE_IPS = [
    ("10.0.1.100", "Internal Office"),
    ("10.0.1.101", "Internal Office"),
    ("10.0.2.50", "VPN Pool"),
    ("10.0.2.51", "VPN Pool"),
    ("192.168.1.10", "Management Network"),
    ("192.168.1.11", "Management Network"),
    ("10.0.0.200", "CI/CD Runner"),
    ("10.0.0.201", "CI/CD Runner"),
]

ATTACKER_IPS = [
    ("203.0.113.50", "Known Scanner"),
    ("203.0.113.100", "Brute Force Node"),
    ("198.51.100.20", "Credential Stuffing"),
    ("198.51.100.30", "Credential Stuffing"),
    ("51.15.200.100", "SSH Scanner (EU)"),
    ("51.15.200.200", "SSH Scanner (EU)"),
    ("185.220.101.1", "Tor Exit Node"),
    ("91.121.89.1", "VPS Scanner"),
    ("5.255.88.100", "Russian Hosting"),
    ("45.33.32.156", "US Scanner"),
]


def timestamp(base=None):
    if base is None:
        base = datetime.datetime.now()
    return base.strftime(TIMESTAMP_FORMAT)


def generate_ssh_log(entries: list):
    base_time = datetime.datetime.now() - datetime.timedelta(hours=24)
    output = []
    for entry in entries:
        ts = timestamp(base_time + datetime.timedelta(seconds=random.randint(0, 86400)))
        output.append(f"{ts} {entry}")
    output.sort()
    return "\n".join(output)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    entries = []

    # 1. Normal legitimate logins (80% of traffic)
    for _ in range(200):
        user = random.choice(USERS[1:])
        ip, desc = random.choice(LEGITIMATE_IPS)
        host = random.choice(HOSTS)
        port = random.randint(10000, 65000)
        auth_method = random.choice(["password", "publickey"])
        entries.append(f"{host} sshd[{random.randint(10000, 99999)}]: Accepted {auth_method} for {user} from {ip} port {port} ssh2")

    # 2. Brute force patterns (10% of traffic)
    for _ in range(3):
        ip, desc = random.choice(ATTACKER_IPS)
        host = random.choice(HOSTS)
        target = random.choice(["root", "admin"])
        for _ in range(random.randint(10, 25)):
            port = random.randint(10000, 65000)
            entries.append(f"{host} sshd[{random.randint(10000, 99999)}]: Failed password for {target} from {ip} port {port} ssh2")

    # 3. Successful brute force (a few)
    for ip, desc in ATTACKER_IPS[:2]:
        host = random.choice(HOSTS)
        target = "root"
        for _ in range(random.randint(5, 10)):
            port = random.randint(10000, 65000)
            entries.append(f"{host} sshd[{random.randint(10000, 99999)}]: Failed password for {target} from {ip} port {port} ssh2")
        port = random.randint(10000, 65000)
        entries.append(f"{host} sshd[{random.randint(10000, 99999)}]: Accepted password for {target} from {ip} port {port} ssh2")

    # 4. Credential stuffing patterns
    for ip, desc in ATTACKER_IPS[2:4]:
        host = random.choice(HOSTS)
        for user in USERS:
            port = random.randint(10000, 65000)
            entries.append(f"{host} sshd[{random.randint(10000, 99999)}]: Failed password for {user} from {ip} port {port} ssh2")

    # 5. Invalid user scans
    for ip, desc in ATTACKER_IPS[4:6]:
        host = random.choice(HOSTS)
        fake_users = ["test", "ubuntu", "ftp", "mysql", "postgres", "git", "www", "nobody", "backup", "info"]
        for user in fake_users:
            port = random.randint(10000, 65000)
            entries.append(f"{host} sshd[{random.randint(10000, 99999)}]: Invalid user {user} from {ip} port {port} ssh2")

    # 6. Off-hours logins (anomaly)
    for _ in range(15):
        user = random.choice(USERS[1:5])
        ip, desc = random.choice(LEGITIMATE_IPS)
        host = random.choice(HOSTS)
        port = random.randint(10000, 65000)
        entries.append(f"{host} sshd[{random.randint(10000, 99999)}]: Accepted password for {user} from {ip} port {port} ssh2")

    # 7. Impossible travel (same user, different continents, same time)
    jdoe_ips = [("10.0.1.100", "US East"), ("203.0.113.200", "Singapore")]
    travel_host = random.choice(HOSTS)
    for ip, loc in jdoe_ips:
        port = random.randint(10000, 65000)
        entries.append(f"{travel_host} sshd[{random.randint(10000, 99999)}]: Accepted password for jdoe from {ip} port {port} ssh2")

    # 8. Sudo commands
    sudo_commands = [
        "/usr/bin/apt update",
        "/usr/bin/systemctl restart sshd",
        "/usr/bin/cat /var/log/auth.log",
        "/usr/bin/tail -f /var/log/syslog",
        "/usr/bin/docker ps -a",
        "/usr/bin/nano /etc/ssh/sshd_config",
        "/usr/bin/useradd newadmin",
        "/usr/bin/passwd root",
    ]
    for cmd in sudo_commands:
        host = random.choice(HOSTS)
        user = random.choice(["admin", "devops"])
        entries.append(f"{host} sudo: {user} : COMMAND={cmd}")

    # Generate and write output
    log_content = generate_ssh_log(entries)

    auth_path = os.path.join(OUTPUT_DIR, "auth.log")
    with open(auth_path, "w") as f:
        f.write(log_content)

    secure_path = os.path.join(OUTPUT_DIR, "secure.log")
    with open(secure_path, "w") as f:
        f.write(log_content)

    print(f"Generated {len(entries)} SSH log entries")
    print(f"  → {auth_path}")
    print(f"  → {secure_path}")
    print()
    print("Attack patterns included:")
    print("  - Brute force attacks (10-25 failed attempts per source)")
    print("  - Successful brute force (break-in after failed attempts)")
    print("  - Credential stuffing (multiple users from same IP)")
    print("  - Invalid user scans (non-existent account attempts)")
    print("  - Off-hours logins (time-based anomalies)")
    print("  - Impossible travel (same user, different continents)")
    print("  - Administrative command audit (sudo commands)")


if __name__ == "__main__":
    main()
