# Detection Rules

Every rule below ships as a **scheduled correlation search** in
`default/savedsearches.conf`. This page documents the logic, the fields it
relies on, and how to tune it.

## Fields

| Field | Source | Notes |
|-------|--------|-------|
| `user` | `transforms.conf` → `ssh_cim_extract` | CIM `user` |
| `src` | `ssh_cim_extract` | CIM `src` (source IP) |
| `action` | `props.conf` → `EVAL-action` | `success` / `failure` |
| `app` | `EVAL-app` | `sshd` |
| `dest` | `EVAL-dest` | message hostname (falls back to `host`) |
| `threat_intel` | `` `ssh_ti_enrich(src)` `` | `TOR_EXIT` / `C2_BLOCKLIST` / `SPAMHAUS_DROP` / "" |

Event types (`default/eventtypes.conf`) and CIM tags (`default/tags.conf`) mark
`action::success` / `action::failure` and `app::ssh` for data-model searches.

Base macros (`default/macros.conf`):

- `` `ssh_events` `` — index + sourcetype
- `` `ssh_failed_logins` `` / `` `ssh_accepted_logins` ``
- `` `ssh_allowlist_filter(<ip>)` `` — drop allowlisted sources
- `` `ssh_ti_enrich(<ip>)` `` — enrich from the live feeds

## Geo enrichment

Geo uses the **built-in `iplocation`** command — no external lookup:

```spl
`ssh_failed_logins`
| rex field=_raw "Failed password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\S+)"
| stats count by src_ip, target_user
| where count >= 10
| iplocation src_ip | table src_ip, City, Country, count
```

## Threat intel

`scripts/update_threat_intel.py` writes three live feeds; `` `ssh_ti_enrich` ``
checks all three and sets `threat_intel`:

```spl
`ssh_events` ("Accepted password" OR "Failed password" OR "Invalid user")
| rex field=_raw "(?<outcome>Accepted|Failed) \S+(?: for)?(?: invalid user)? (?<user>\S+) from (?<src_ip>\S+)"
| `ssh_ti_enrich(src_ip)`
| where threat_intel != ""
| stats count values(user) as users by src_ip, threat_intel
```

Spamhaus ranges are CIDR-matched (`match_type = CIDR(src_ip)` in
`transforms.conf`); Tor and abuse.ch feeds match exact IPs.

## Impossible travel

Sort per user, then bind the **previous** event with `streamstats
current=f window=1 last(...)` and compute great-circle speed:

```spl
`ssh_accepted_logins`
| rex field=_raw "Accepted \S+ for (?<user>\S+) from (?<src>\S+)"
| iplocation src | where isnotnull(lat)
| sort 0 user +_time
| streamstats current=f window=1 last(_time) as prev_time last(lat) as prev_lat last(lon) as prev_lon by user
| eval hours = round((_time - prev_time) / 3600, 2)
| eval distance_km = round(6371 * 2 * asin(sqrt(pow(sin(((lat - prev_lat) * pi() / 180) / 2), 2) + cos(prev_lat * pi() / 180) * cos(lat * pi() / 180) * pow(sin(((lon - prev_lon) * pi() / 180) / 2), 2))), 1)
| eval speed_kmh = if(hours > 0, round(distance_km / hours, 1), null())
| where distance_km > 500 AND (isnull(hours) OR speed_kmh > 900)
```

**Tuning:** raise `distance_km` / lower `speed_kmh` for noisy travel; exclude
VPN egress in `ssh_allowlist.csv`.

## False positives

1. **Allowlist first.** Put internal ranges, VPN pools and CI runners in
   `lookups/ssh_allowlist.csv`.

   ```csv
   src_ip,allow_reason,owner,added
   203.0.113.10,Corporate VPN,IT,2026-01-01
   10.0.0.0/8,Internal network,Infra,2026-01-01
   ```

   The `` `ssh_allowlist_filter` `` macro drops matching `src_ip`. Exact-match
   rows work directly; for CIDR rows use `cidrmatch` or a CIDR lookup:

   ```spl
   | where NOT cidrmatch("10.0.0.0/8", src_ip)
   ```

2. **Baseline before tightening.** Run each search over `earliest=-7d` and look
   at the distribution; move thresholds above the normal 99th percentile.
3. **Services accounts.** `svc_*` logins are deliberately low-noise; if they
   are expected, allowlist them by user rather than disabling the rule.

## MITRE ATT&CK coverage

| Technique | ID | Search |
|-----------|-----|--------|
| Brute Force | T1110 | SSH - Brute Force Detection |
| Brute Force: Password Spraying | T1110.003 | SSH - Distributed Brute Force Detection |
| Brute Force: Credential Stuffing | T1110.004 | SSH - Credential Stuffing Detection |
| Valid Accounts | T1078 | SSH - Successful Brute Force / Impossible Travel |
| Valid Accounts: Default Accounts | T1078.002 | SSH - Dormant Account Login |
| Valid Accounts: Local Accounts | T1078.003 | SSH - Privileged Account Login |
| Proxy: External Proxy | T1090 | SSH - Threat Intel Match |
