"""
SSH Log Generator

Generates realistic sample SSH authentication logs for testing Splunk
detection rules and dashboards without needing real infrastructure.

Attacker source IPs are drawn from the LIVE threat-intel lookups written by
scripts/update_threat_intel.py (Tor exit list, abuse.ch Feodo C2 blocklist,
Spamhaus DROP). That way the shipped sample data actually exercises the app's
threat-intel enrichment instead of never matching a feed. If the lookup files
are absent, the built-in fallback list is used.

Attack attempts are clustered into short bursts and one burst is placed in the
last few minutes, so time-windowed scheduled searches (-5m / -10m) can fire on
freshly generated data.

Usage:
    python generate-sample-logs.py

Output:
    ./output/auth.log    - generated SSH auth log
    ./output/secure.log  - RHEL/CentOS flavoured copy
"""
import os
import random
import datetime
import sys

# Windows console (cp1252) cannot encode non-ASCII output.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Write next to the repo (scripts/../output) so the script works no matter
# which directory it is launched from.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(REPO_ROOT, "output")
TIMESTAMP_FORMAT = "%b %d %H:%M:%S"
DAY = 86400  # generator spans the last 24h; offsets are seconds from (now-24h)

USERS = ["root", "admin", "jdoe", "asmith", "devops", "oracle", "svc_backup",
         "deploy", "test_user", "ansible", "nagios", "docker", "guest"]
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

# Fallback only - real attacker IPs come from the lookups when available.
ATTACKER_IPS = [
    ("203.0.113.50", "Known Scanner"),
    ("203.0.113.100", "Brute Force Node"),
    ("198.51.100.20", "Credential Stuffing"),
    ("198.51.100.30", "Credential Stuffing"),
    ("185.220.101.1", "Tor Exit Node"),
]


def load_feed_ips():
    """Return [(ip, label)] sampled from the live lookups, real ones only."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sources = [
        ("tor_exit_nodes.csv", "Tor Exit Node"),
        ("c2_blocklist.csv", "C2 Server (Feodo)"),
        ("spamhaus_drop.csv", "Spamhaus DROP netblock"),
    ]
    picks = []
    for fname, label in sources:
        path = os.path.join(root, "lookups", fname)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                rows = [ln.strip() for ln in fh
                        if ln.strip() and not ln.lower().startswith("src_ip")]
        except OSError:
            continue
        for row in rows[:3]:
            ip = row.split(",")[0].strip()
            if "/" in ip:  # CIDR block -> use an address inside it
                parts = ip.split("/")[0].split(".")
                ip = ".".join(parts[:3]) + "." + str((int(parts[3]) % 250) + 1)
            picks.append((ip, label))
    return picks


def add(entries, offset, host, message):
    entries.append((offset, "%s sshd[%d]: %s" % (host, random.randint(10000, 99999), message)))


def burst(entries, ip, host, target, count, start, span=90):
    """Cluster `count` attempts from one IP into a tight time window."""
    for _ in range(count):
        add(entries, start + random.randint(0, span), host,
            "Failed password for %s from %s port %d ssh2"
            % (target, ip, random.randint(10000, 65000)))


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    base_time = datetime.datetime.now() - datetime.timedelta(seconds=DAY)
    now_off = DAY - 210        # ~3.5 minutes ago - safely inside a -5m window
    entries = []

    feed = load_feed_ips()
    attackers = feed if feed else ATTACKER_IPS
    # Put one IP per feed category first so the patterns below exercise every
    # enrichment class (Tor exit / C2 / Spamhaus netblock), then the rest.
    seen_labels, varied = set(), []
    for item in attackers:
        if item[1] not in seen_labels:
            seen_labels.add(item[1])
            varied.append(item)
    varied += [it for it in attackers if it not in varied]
    attackers = varied

    # 1. Normal legitimate logins (bulk of traffic)
    for _ in range(200):
        ip, _ = random.choice(LEGITIMATE_IPS)
        add(entries, random.randint(0, DAY), random.choice(HOSTS),
            "Accepted %s for %s from %s port %d ssh2"
            % (random.choice(["password", "publickey"]), random.choice(USERS[1:]),
               ip, random.randint(10000, 65000)))

    # 2. Brute-force bursts - one lands in the last few minutes so a
    #    scheduled -5m search can fire; the rest scatter across the day.
    bf_ips = attackers[:min(3, len(attackers))]
    for idx, (ip, _) in enumerate(bf_ips):
        start = now_off + random.randint(0, 60) if idx == 0 else random.randint(0, DAY - 300)
        burst(entries, ip, random.choice(HOSTS), random.choice(["root", "admin"]),
              random.randint(12, 25), start, span=60)

    # 3. Successful brute force (break-in after failures) - tight window
    for ip, _ in bf_ips[:2]:
        start = random.randint(0, DAY - 300)
        target = "root"
        host = random.choice(HOSTS)
        burst(entries, ip, host, target, random.randint(6, 10), start)
        add(entries, start + 100, host,
            "Accepted password for %s from %s port %d ssh2"
            % (target, ip, random.randint(10000, 65000)))

    # 4. Credential stuffing (many users from one IP in a short window)
    for ip, _ in attackers[:2]:
        start = random.randint(0, DAY - 300)
        for user in USERS:
            add(entries, start + random.randint(0, 120), random.choice(HOSTS),
                "Failed password for %s from %s port %d ssh2"
                % (user, ip, random.randint(10000, 65000)))

    # 5. Invalid-user scans
    for ip, _ in (attackers[1:3] if len(attackers) >= 3 else ATTACKER_IPS[:1]):
        start = random.randint(0, DAY - 300)
        for user in ["test", "ubuntu", "ftp", "mysql", "postgres", "git", "www",
                     "nobody", "backup", "info"]:
            add(entries, start + random.randint(0, 180), random.choice(HOSTS),
                "Invalid user %s from %s port %d ssh2"
                % (user, ip, random.randint(10000, 65000)))

    # 6. Off-hours logins (anomaly context)
    for _ in range(15):
        ip, _ = random.choice(LEGITIMATE_IPS)
        add(entries, random.randint(0, DAY), random.choice(HOSTS),
            "Accepted password for %s from %s port %d ssh2"
            % (random.choice(USERS[1:5]), ip, random.randint(10000, 65000)))

    # 7. Impossible travel (same user, two continents, seconds apart)
    travel_host = random.choice(HOSTS)
    t0 = random.randint(0, DAY - 120)
    for off, ip in ((0, "10.0.1.100"), (60, "203.0.113.200")):
        add(entries, t0 + off, travel_host,
            "Accepted password for jdoe from %s port %d ssh2"
            % (ip, random.randint(10000, 65000)))

    # 8. Sudo command audit
    for cmd in ["/usr/bin/apt update", "/usr/bin/systemctl restart sshd",
                "/usr/bin/cat /var/log/auth.log", "/usr/bin/tail -f /var/log/syslog",
                "/usr/bin/docker ps -a", "/usr/bin/nano /etc/ssh/sshd_config",
                "/usr/bin/useradd newadmin", "/usr/bin/passwd root"]:
        entries.append((random.randint(0, DAY),
                        "%s sudo: %s : COMMAND=%s"
                        % (random.choice(HOSTS), random.choice(["admin", "devops"]), cmd)))

    output = []
    for off, text in sorted(entries, key=lambda t: t[0]):
        ts = (base_time + datetime.timedelta(seconds=off)).strftime(TIMESTAMP_FORMAT)
        output.append("%s %s" % (ts, text))
    content = "\n".join(output)

    for name in ("auth.log", "secure.log"):
        with open(os.path.join(OUTPUT_DIR, name), "w") as fh:
            fh.write(content)

    print("Generated %d SSH log entries" % len(entries))
    if feed:
        print("Attacker IPs drawn from live feeds (%d):" % len(feed))
        for ip, label in feed:
            print("  - %s  (%s)" % (ip, label))
    else:
        print("No lookups found - using fallback attacker list "
              "(run scripts/update_threat_intel.py first)")
    print("  -> %s" % os.path.join(OUTPUT_DIR, "auth.log"))
    print("  -> %s" % os.path.join(OUTPUT_DIR, "secure.log"))
    print()
    print("Attack patterns included:")
    print("  - Brute-force bursts (12-25 attempts per source, clustered)")
    print("  - One burst inside the last 5 minutes (fires -5m scheduled searches)")
    print("  - Successful brute force (break-in after failures)")
    print("  - Credential stuffing (every account from one IP)")
    print("  - Invalid user scans")
    print("  - Off-hours logins, impossible travel, sudo command audit")


if __name__ == "__main__":
    main()
