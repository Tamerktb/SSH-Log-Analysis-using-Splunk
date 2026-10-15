# Deployment Guide — SSH Log Analysis (Splunk App)

Deploys the **SSHLogAnalysis** app to Splunk Enterprise / Cloud and points it at
live SSH authentication logs. Follow top to bottom; the checklist at the end
confirms a working install.

## Requirements

- **Splunk Enterprise 9.x or 10.x** (Search Head + Indexer, standalone is fine),
  or Splunk Cloud with app upload enabled.
- A **Universal Forwarder** on each Linux host producing `/var/log/auth.log`
  (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS/Rocky).
- **Python 3** on the host that runs `update_threat_intel.py` (only needs the
  standard library) and outbound HTTPS to the feed hosts.
- Role with `admin` or `power` + `edit_knowledge` to load the app.
- Optional: **Splunk Add-on for Unix and Linux (`Splunk_TA_nix`)** — recommended
  for base `sourcetype=linux_secure` parsing. The app works without it.

> **Geo-IP:** the searches use Splunk's built-in **`iplocation`** command.
> No `.mmdb` upload and no custom `geoip` lookup is required.

---

## 1. Create the index

```bash
$SPLUNK_HOME/bin/splunk add index linux_secure -auth admin:<password>
```

The index name is referenced once, by the `` `ssh_events` `` macro in
`default/macros.conf`. If your standard index differs, edit that macro.

## 2. Install the app

The app must live in a directory named **`SSHLogAnalysis`** (matches
`[package] id` in `default/app.conf`):

```bash
git clone https://github.com/Tamerktb/SSH-Log-Analysis-using-Splunk.git
mv SSH-Log-Analysis-using-Splunk $SPLUNK_HOME/etc/apps/SSHLogAnalysis
chown -R splunk:splunk $SPLUNK_HOME/etc/apps/SSHLogAnalysis

# Refresh live threat-intel feeds into the app's lookups
python3 $SPLUNK_HOME/etc/apps/SSHLogAnalysis/bin/update_threat_intel.py \
        --out $SPLUNK_HOME/etc/apps/SSHLogAnalysis/lookups

$SPLUNK_HOME/bin/splunk restart -auth admin:<password>
```

Splunk Cloud: tar the folder (`tar -czf SSHLogAnalysis.tgz SSHLogAnalysis`) and
upload via **Apps ▸ Manage Apps ▸ Install app from file**.

## 3. Deploy the forwarder input

On each monitored host, copy `default/inputs.conf` to
`$SPLUNK_HOME/etc/system/local/inputs.conf` (or push it via a deployment app)
and restart the forwarder:

```
[monitor:///var/log/auth.log]
disabled = 0
index = linux_secure
sourcetype = linux_secure
crcSalt = <SOURCE>
```

`crcSalt = <SOURCE>` prevents log rotation from dropping data.

### Alternative: rsyslog → Splunk (no Universal Forwarder)

If you cannot install a forwarder — or want a fast lab pipeline — have the
host's **rsyslog** ship the `auth`/`authpriv` facilities straight to a Splunk
TCP input. This is a real pattern, not a toy: over TCP it is lossless, and it
needs no agent on the host.

**On the indexer** — `$SPLUNK_HOME/etc/system/local/inputs.conf`. Receiver
config goes in `system/local`, **not** in the app: the app is also deployed to
forwarders, where a listening input would be wrong.

```
[tcp://514]
connection_host = ip
index = linux_secure
sourcetype = linux_secure
```

Open the port (Linux: `firewall-cmd --add-port=514/tcp --permanent` or
`ufw allow 514/tcp`; Windows: an inbound rule for TCP 514) and restart Splunk.
`connection_host = ip` sets `host` to the sender's IP; the app's
`EXTRACT-msg_host` still lifts the hostname out of the line into `msg_host`.

**On each Linux source host** — `/etc/rsyslog.d/60-splunk-forward.conf`:

```
template(name="SplunkAuth" type="string" string="%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n")

auth,authpriv.* action(type="omfwd"
                       target="<indexer-ip>"
                       port="514"
                       protocol="tcp"
                       template="SplunkAuth"
                       action.resumeRetryCount="-1"
                       queue.type="linkedList"
                       queue.size="10000")
```

Reload with `systemctl restart rsyslog`; validate the syntax with
`rsyslogd -N1`. The template reproduces the plain `auth.log` line format, so
`TZ`/sourcetype handling and the SSH field extractions apply unchanged.

> **Two caveats.** (1) `%TIMESTAMP%` is the *host's* local time — if the host
> is not on UTC, set `TZ` in `default/props.conf` to that zone, or timestamps
> will be skewed. (2) rsyslog collapses identical repeats into a
> `message repeated N times:` line, which can hide volume from any counting
> search. A forwarder does not do this.

**Verified end to end:** a 20-password `hydra` run from a Kali host against a
lab Ubuntu 22.04 victim (rsyslog → Splunk `:514`) arrived as exactly **20 events
across the same 4 source ports**, and `SSH - Brute Force Detection` returned the
source IP with `severity = HIGH`.

## 4. Keep threat intel current

Two supported ways — pick one:

**A. Splunk scripted input (in-app, daily).** Enable the stanza in
`default/inputs.conf`:

```
[script://./bin/update_threat_intel.py]
disabled = 0
interval = 86400
sourcetype = ssh_threat_intel_update
index = _internal
```

**B. OS cron.** `0 3 * * *  python3 .../bin/update_threat_intel.py`.

Test any time without writing files:

```bash
python3 bin/update_threat_intel.py --dry-run
```

## 5. Lookup permissions

`metadata/default.meta` already grants read to `*` and write to `admin`/`power`.
If your Splunk admin requires object sharing, confirm under
**Settings ▸ Lookups ▸ Lookup Definitions** that the six definitions from
`default/transforms.conf` are visible to the roles that run the searches.

## 6. CIM acceleration (optional, recommended at scale)

The app tags events for the **Authentication** data model. To run the
`tstats` searches in `spl-queries/cim-authentication.spl`:

**Settings ▸ Data models ▸ Authentication ▸ Edit ▸ Acceleration** → enable.

## 7. Verify

```bash
python3 tools/validate_repo.py              # 15 static checks
python3 bin/update_threat_intel.py --dry-run
```

In Splunk:

- [ ] `index=linux_secure sourcetype=linux_secure | stats count` returns events
- [ ] `` `ssh_events` | stats count `` expands (macros loaded)
- [ ] `| tstats count from datamodel=Authentication.Authentication` is non-zero
- [ ] **SSH Log Analysis** app shows the two dashboards
- [ ] `SSH - Threat Intel Match` fires for a source IP that is in
      `lookups/tor_exit_nodes.csv`
- [ ] No `lookup` / `iplocation` errors in the job status bar

## 8. Tuning & operations

- **Allowlist internal sources** in `lookups/ssh_allowlist.csv`
  (`src_ip,allow_reason,owner,added`) — internal ranges, VPN pools, CI runners.
  Recommend `cidrmatch` for CIDR rows; the `` `ssh_allowlist_filter` `` macro
  drops anything present.
- **Thresholds** are per-search in `default/savedsearches.conf`
  (`count >= 10`, `unique_users >= 15`, speed `> 900 km/h`, ...). Baseline a week
  of events before tightening.
- **Alert routing** — replace `soc@example.com` and set `action.email = 1` (or
  add Slack/PagerDuty via `alert_actions.conf`).
- **Suppression** — `alert.suppress.fields` + `alert.suppress.period` are set per
  search to prevent alert storms from a single source.

## Uninstall

```bash
$SPLUNK_HOME/bin/splunk stop
rm -rf $SPLUNK_HOME/etc/apps/SSHLogAnalysis
$SPLUNK_HOME/bin/splunk start
```

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Searches return nothing | Index name mismatch — edit `` `ssh_events` `` in `default/macros.conf` |
| `Could not find lookup` | Feed not pulled — run `update_threat_intel.py`; verify with `--dry-run` |
| auth.log parsed as one event | Remove `Splunk_TA_nix` duplication, or check `props.conf` line-breaking |
| `iplocation` gives no City | Source IPs are private/RFC1918 — expected for internal sources |
| Feed script fails | No outbound HTTPS (proxy) — set `HTTP_PROXY`/`HTTPS_PROXY` for the script |
