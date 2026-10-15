#!/usr/bin/env python3
"""
Download live threat-intel feeds into the app's lookups/ directory.

Public feeds, no API key required:
  Tor bulk exit list  check.torproject.org            -> every current Tor exit
  abuse.ch Feodo      feodotracker.abuse.ch           -> botnet C2 IPs
  abuse.ch SSLBL      sslbl.abuse.ch                  -> malicious TLS cert IPs
  Spamhaus DROP       spamhaus.org/drop               -> hijacked/spam CIDRs

Outputs (columns match the lookup definitions in default/transforms.conf):
  lookups/tor_exit_nodes.csv   src_ip,tor_node_source,last_seen
  lookups/c2_blocklist.csv     src_ip,c2_source,last_seen
  lookups/spamhaus_drop.csv    src_ip,sbl_reference,last_seen

Usage (from the repo root):
  python bin/update_threat_intel.py
  python bin/update_threat_intel.py --only tor,c2
  python bin/update_threat_intel.py --dry-run

This script is bundled in the app's bin/ directory, which is the location
Splunk expects for scripts it executes (see the scripted-input stanza in
default/inputs.conf).
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = "Mozilla/5.0 (compatible; SSHLogAnalysis/1.0; threat-intel-updater)"
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
TODAY = datetime.date.today().isoformat()


def fetch(url, timeout=40):
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept": "text/plain, application/json, */*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def valid_ip(text):
    if not IPV4.match(text):
        return False
    return all(0 <= int(o) <= 255 for o in text.split("."))


def valid_cidr(text):
    if not CIDR.match(text):
        return False
    ip, bits = text.split("/")
    return valid_ip(ip) and 0 <= int(bits) <= 32


def lines(text):
    for raw in text.splitlines():
        raw = raw.strip()
        if raw and not raw.startswith(("#", ";")):
            yield raw


def parse_tor(text, url=None):
    out = {}
    for ln in lines(text):
        ip = ln.split(",")[0].split()[0].strip()
        if valid_ip(ip):
            out[ip] = "torproject_bulk_exitlist"
    return out


def parse_c2(text, source):
    out = {}
    for ln in lines(text):
        tok = ln.split(";")[0].split(",")[0].strip()
        ip = tok.split(":")[0].strip()
        if valid_ip(ip):
            out[ip] = source
    return out


def parse_spamhaus(text, url):
    out = {}
    if url.endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            return out
        for rec in data:
            cidr = str(rec.get("cidr", "")).strip()
            if valid_cidr(cidr):
                out[cidr] = str(rec.get("sblid") or "SPAMHAUS_DROP")
        return out
    for ln in lines(text):
        parts = ln.split(";")
        cidr = parts[0].strip()
        ref = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "SPAMHAUS_DROP"
        if valid_cidr(cidr):
            out[cidr] = ref
    return out


# group -> output file, value column, and (url, parser) sources
FEEDS = {
    "tor": {
        "out": "tor_exit_nodes.csv",
        "cols": ["src_ip", "tor_node_source", "last_seen"],
        "sources": [("https://check.torproject.org/torbulkexitlist", parse_tor)],
    },
    "c2": {
        "out": "c2_blocklist.csv",
        "cols": ["src_ip", "c2_source", "last_seen"],
        "sources": [
            ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
             lambda t, u: parse_c2(t, "feodo_tracker")),
            ("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
             lambda t, u: parse_c2(t, "abuse_ch_sslbl")),
        ],
    },
    "spamhaus": {
        "out": "spamhaus_drop.csv",
        "cols": ["src_ip", "sbl_reference", "last_seen"],
        "sources": [
            ("https://www.spamhaus.org/drop/drop_v4.json", parse_spamhaus),
            ("https://www.spamhaus.org/drop/drop.txt", parse_spamhaus),
        ],
    },
}


def run_group(name, spec, out_dir, dry_run):
    merged, used = {}, []
    for url, parser in spec["sources"]:
        try:
            text = fetch(url)
            hits = parser(text, url)
        except Exception as exc:  # noqa: BLE001 - report and continue
            print("  [WARN] %s source failed: %s (%s)" % (name, url, exc))
            continue
        if hits:
            used.append("%s=%d" % (url.rsplit("/", 1)[-1] or url, len(hits)))
            for key, val in hits.items():
                merged.setdefault(key, val)
    if not merged:
        print("  [FAIL] %s: no usable rows from any source" % name)
        return 0
    path = os.path.join(out_dir, spec["out"])
    if dry_run:
        print("  [DRY ] %s: %d rows -> %s (%s)"
              % (name, len(merged), spec["out"], ", ".join(used)))
        return len(merged)
    os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(",".join(spec["cols"]) + "\n")
        for key in sorted(merged):
            fh.write("%s,%s,%s\n" % (key, merged[key], TODAY))
    print("  [ OK ] %s: %d rows -> %s (%s)"
          % (name, len(merged), spec["out"], ", ".join(used)))
    return len(merged)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    ap = argparse.ArgumentParser(description="Update SSH app threat-intel lookups")
    ap.add_argument("--out", default=os.path.join(root, "lookups"),
                    help="output directory for the CSV lookups")
    ap.add_argument("--only", default="", help="comma list of feed groups: tor,c2,spamhaus")
    ap.add_argument("--dry-run", action="store_true", help="fetch and count, do not write")
    args = ap.parse_args()

    wanted = [g.strip() for g in args.only.split(",") if g.strip()] or list(FEEDS)
    unknown = [g for g in wanted if g not in FEEDS]
    if unknown:
        print("Unknown feed group(s): %s" % ", ".join(unknown))
        return 2

    print("Updating threat-intel lookups (%s)\n" % TODAY)
    total = 0
    for name in wanted:
        total += run_group(name, FEEDS[name], args.out, args.dry_run)
    print("\nTotal indicator rows: %d" % total)
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
