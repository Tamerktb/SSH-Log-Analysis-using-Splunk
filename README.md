# SSH Log Analysis — Splunk App

A deployable **Splunk app** for SSH authentication monitoring: parsing, CIM
field mapping, scheduled correlation searches, dashboards, and **live
threat-intel feeds**. Built to run against real `sshd` logs on real Splunk
(Either Splunk Enterprise 9.x / 10.x or Splunk Cloud with app upload).

![Architecture](https://github.com/Tamerktb/SSH-Log-Analysis-using-Splunk/blob/main/df3ul9s9oiv.jpg?raw=true)

## What it detects

| Detection | Signal | MITRE ATT&CK |
|-----------|--------|--------------|
| Brute force | 10+ failed logins / source IP / 5 min | T1110 |
| Distributed brute force | 8+ source IPs against one account | T1110.003 |
| Credential stuffing | 15+ usernames from one source in 2 min | T1110.004 |
| Successful brute force | Accepted login after repeated failures | T1078 / T1110 |
| Impossible travel | Two logins too far apart in the elapsed time | T1078 |
| Off-hours login | Successful logins before 06:00 / after 22:00 | T1078 |
| Dormant account login | Account silent 7 days, login in last 15 min | T1078.002 |
| Threat-intel match | Source IP on Tor / abuse.ch C2 / Spamhaus DROP | T1078 / T1090 |
| Privileged login | Direct login to `root` / `admin` / `svc_*` | T1078.003 |

## Live threat-intel feeds (not sample data)

`scripts/update_threat_intel.py` pulls real, public feeds straight into the
app's lookups:

| Feed | Source | Lookup |
|------|--------|--------|
| Tor bulk exit list | `check.torproject.org` | `lookups/tor_exit_nodes.csv` |
| Feodo Tracker C2 | `feodotracker.abuse.ch` | `lookups/c2_blocklist.csv` |
| SSLBL C2 (TLS) | `sslbl.abuse.ch` | `lookups/c2_blocklist.csv` |
| Spamhaus DROP | `spamhaus.org/drop` | `lookups/spamhaus_drop.csv` |

The lookup files ship with a real snapshot (taken at commit time) and are
refreshed by running the script — see [Operations](#operations). Spamhaus
ranges are matched with `match_type = CIDR(src_ip)`; the IP feeds match exactly.

## App layout

```
SSHLogAnalysis/
├── default/
│   ├── app.conf                # app manifest (id: SSHLogAnalysis)
│   ├── inputs.conf             # monitor auth.log / secure on the forwarder
│   ├── props.conf              # linux_secure parsing + CIM field mapping
│   ├── transforms.conf         # field extractions + lookup definitions
│   ├── eventtypes.conf         # ssh_login_success / failure / invalid user ...
│   ├── tags.conf               # action::success|failure, app::ssh (CIM)
│   ├── macros.conf             # base searches + enrichment macros
│   ├── savedsearches.conf      # 9 scheduled correlation searches
│   └── data/ui/views/          # ssh-threat-dashboard.xml, ssh-monitoring-dashboard.xml
├── lookups/                    # CSV lookups (feeds + allowlist + watchlist)
├── metadata/default.meta       # object permissions
├── spl-queries/                # ad-hoc SPL triage library (.spl)
├── sample-data/                # test fixtures for validating detections
├── scripts/
│   ├── update_threat_intel.py  # refresh the live feeds
│   ├── generate-sample-logs.py # generate test logs (fixtures)
│   └── validate_repo.py        # 12 static deployment checks
└── docs/
```

## Install

Deploy as an app so every knowledge object (macros, lookups, event types,
searches, views) loads together — no manual copy/paste:

```bash
# 1. Put the app in place (folder name MUST be SSHLogAnalysis)
git clone https://github.com/Tamerktb/SSH-Log-Analysis-using-Splunk.git
mv SSH-Log-Analysis-using-Splunk $SPLUNK_HOME/etc/apps/SSHLogAnalysis

# 2. Refresh the live threat-intel feeds
python $SPLUNK_HOME/etc/apps/SSHLogAnalysis/scripts/update_threat_intel.py \
       --out $SPLUNK_HOME/etc/apps/SSHLogAnalysis/lookups

# 3. Restart (or Debug/Refresh) to load the app
$SPLUNK_HOME/bin/splunk restart
```

Then, on the **forwarder**, take `default/inputs.conf` to monitor
`/var/log/auth.log` (Debian/Ubuntu) and `/var/log/secure` (RHEL family). The
index `linux_secure` is referenced by the `` `ssh_events` `` macro — change it
in one place (`default/macros.conf`) if your index differs.

> If the official **Splunk Add-on for Unix and Linux (`Splunk_TA_nix`)** is
> installed, it handles base parsing for `sourcetype=linux_secure`; this app's
> CIM mapping and detections layer on top of it.

## CIM alignment

Events are tagged for the **Authentication** data model (`action::success`,
`action::failure`, `app::ssh`) and the app maps CIM fields — `src`, `user`,
`dest`, `action`, `app`, `vendor_product` — so tstats/data-model searches and
ES work without extra config:

```spl
| tstats count from datamodel=Authentication.Authentication
    where Authentication.action=failure by Authentication.src, Authentication.user
| sort - count
```

## Operations

**Refresh feeds** (recommended: daily). Add a cron entry or a Splunk scripted
input:

```bash
python scripts/update_threat_intel.py           # all feeds
python scripts/update_threat_intel.py --only tor,c2
python scripts/update_threat_intel.py --dry-run # fetch + count, do not write
```

**Tune false positives.** Add internal / VPN / CI sources to
`lookups/ssh_allowlist.csv` (`src_ip,allow_reason,owner,added`); the
`` `ssh_allowlist_filter` `` macro drops them from the alerts.

**Internal watchlist.** `lookups/known_attackers.csv` is an analyst-maintained
(`src_ip,threat_type,confidence,source`) list, intentionally empty — add your
own known-bad actors; the `` `ssh_watchlist_enrich` `` macro enriches with it.

**Alert routing.** Point `action.email.to` at your on-call alias (replace
`soc@example.com`) and set `action.email = 1`. Thresholds live next to each
search in `default/savedsearches.conf`.

## Verify

```bash
python scripts/validate_repo.py    # 12 deployment checks -> "all checks PASSED"
python scripts/update_threat_intel.py --dry-run
```

In Splunk, after onboarding logs:

- [ ] `index=linux_secure sourcetype=linux_secure | stats count` returns events
- [ ] `| tstats count from datamodel=Authentication.Authentication` is non-zero
- [ ] `` `ssh_events` | stats count `` expands without error
- [ ] Threat + monitoring dashboards render (map, tables, impossible travel)
- [ ] `SSH - Threat Intel Match` fires against a Tor exit IP from the feed
- [ ] No `lookup` errors in the job status bar

## Ad-hoc triage library

`spl-queries/*.spl` holds ready-to-paste searches for manual investigation
(brute force, credential stuffing, geo/threat-intel, user behaviour, anomaly
detection, CIM via `tstats`). They use built-in `iplocation` for geo — no
external `.mmdb` upload and no `geoip` lookup required.

## License

MIT — see `LICENSE`.
