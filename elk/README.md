# ELK / Elastic Stack port

The nine `SSHLogAnalysis` correlation searches, running on Elastic 8.15 + ElastAlert 2
instead of Splunk. Same `event.action` vocabulary, same severity mapping, same MITRE
techniques - a second implementation of `default/savedsearches.conf`, not a replacement.

```
filebeat 8.15.0  ->  filebeat-8.15.0 data stream
                     (ingest pipeline ssh-auth-pipeline)
                        |
                        +-- 6 parse processors   (grok + date + ECS script)  -> event.action/outcome/source.ip/user.name
                        +-- 8 enrich processors  (geoip + 5 enrich + script) -> threat_intel, allow_reason, source.geo
                                   ^
        indicator feeds --------/ (Tor exit nodes, abuse.ch Feodo C2, Spamhaus DROP, allowlist)
                                            |
                                    ElastAlert 2 (9 rules) -> elastalert_status writeback index
```

## Layout

| Path | Purpose |
| --- | --- |
| `setup/deploy_elk.py` | Idempotent deployer: refreshes the 5 threat-intel feeds, creates/deletes/re-executes the 5 enrich policies, publishes both ingest pipelines (`ssh-auth-pipeline` = the 14 composed processors, `ssh-auth-enrich` = the 8 enrichment processors alone), then reports field coverage. |
| `elasticsearch/pipeline-ssh-auth.json` | Parse half: 16 grok patterns -> ECS (`event.action/outcome/category/dataset/module`, `system.auth.ssh.*`, `user.name`, `source.ip`). Timestamps are UTC. |
| `elasticsearch/pipeline-ssh-auth-enrich.json` | Enrich half: `geoip` -> `source.geo`, threat-intel enrich processors, allowlist, flatten script, temp-field cleanup. |
| `elastalert2/config.yaml` | ElastAlert 2 config (1 m runs, 15m buffer, writeback index `elastalert_status`). |
| `elk/elastalert2/rules/01..09-*.yaml` | The nine detections, each header commenting the Splunk search it mirrors.
- `elk/docker-compose.elastalert2.yml`: overlay service for the Elasticsearch/Kibana/Filebeat stack (mounts config, rules, and the custom module into `/opt/elastalert/`).
- `elk/elastalert2/ssh_ruletypes.py`: custom rule types for the four detections that a built-in ElastAlert type cannot express.
- `elk/elastalert2/tests/`: `--data` fixtures + runner (regression tests for those four types).

## Rule parity

| # | Splunk search (default/savedsearches.conf) | ELK rule | type |
|---|---|---|---|
| 01 | Brute force, 10 failed / 5m by src_ip | `01-ssh-brute-force.yaml` | built-in `frequency` |
| 02 | `dc(src_ip)>=8 AND count>=20 by target_user` | `02-ssh-distributed-brute-force.yaml` | `SshDistributedBruteForce` |
| 03 | `dc(target_user)>=15 AND count>=20 by src_ip` | `03-ssh-credential-stuffing.yaml` | `SshCredentialStuffing` |
| 04 | `failed>=5 AND success>0 by src_ip, target_user` | `04-ssh-brute-force-success.yaml` | `SshBruteForceSuccess` |
| 05 | accepted logins >=500 km apart in <=1 h | `05-ssh-impossible-travel.yaml` | `SshImpossibleTravel` |
| 06 | off-hours logins (analyst TZ) | `06-ssh-off-hours-login.yaml` | frequency + Painless |
| 07 | first-ever login for an account in 7 d | `07-ssh-dormant-account-login.yaml` | `new_term` |
| 08 | threat-intel match on src_ip | `08-ssh-threat-intel-match.yaml` | `any` + `threat_intel_match` |
| 09 | privileged/service account logins | `09-ssh-privileged-account-login.yaml` | `any` + terms/prefix |

Rules 02-05 cannot be built from ElastAlert 2's rule types: Splunk's `stats` returns a
DISTINCT count and a TOTAL count from one pass (CardinalityRule tracks only distinct
values), and Impossible Travel needs haversine arithmetic that Elasticsearch cannot
evaluate in a query. Those four live in `ssh_ruletypes.py`.

## Deploy

```bash
# 1) pipelines + enrich policies + threat-intel feeds (run against the ES host)
python3 elk/setup/deploy_elk.py            # add --dry-run to preview

# 2) the rules engine (overlay onto the existing stack)
cd elk && docker-compose -f docker-compose.yml -f docker-compose.elastalert2.yml \
     up -d --no-deps elastalert2
docker logs -f elastalert2

# 3) regression-test the four custom rule types (no cluster required - fixtures)
bash elk/elastalert2/tests/run_tests.sh
```

`--no-deps` matters: the lab stack's containers were started outside this compose
project, so `up` would otherwise try to recreate `elasticsearch` and abort with
`container name "/es" is already in use`.

## Verification (Ubuntu 22.04 + ES 8.15, Oct 2026)

| Check | Result |
|---|---|
| Pipeline processors | `ssh-auth-pipeline` = 14 (6 parse + 8 enrich), `ssh-auth-enrich` = 8 |
| Enrichment screenshots | `TOR_EXIT` / `C2_BLOCKLIST` / `SPAMHAUS_DROP` (`ip_range`) all matched real feed IPs |
| Field coverage | `event.action`, `source.ip`, `threat_intel`, `source.geo.country_iso_code` populated |
| Custom rule types (fixtures) | 4/4 pass, 1 match each, no false positive on a same-city login pair |
| Schema validation | 9/9 rules OK |
| Live service | all 9 rules run every minute, 0 error docs in `elastalert_status_error` |
| Live detections | threat-intel, off-hours, privileged login, and (on a hydra burst from Kali) brute-force + credential-stuffing + distributed brute force |
| Live alert | `dc=15` accounts from one IP, and `dc=8` source IPs on one account, written to `elastalert_status` |

The burst used `hydra -L users.txt` for credential stuffing (15 accounts from one host)
and `ssh -b <src>` over 8 secondary addresses for the distributed case.

## Notes / deliberate divergences

- **Timezone**: `linux_secure` syslog carries no TZ, so the Splunk app declares
  `TZ = UTC`. The ELK side records `@timestamp` in UTC too, and Filebeat ships the
  actual file. Rule 06 is the only rule that depends on the analyst's local time
  (`utc_offset_hours`).
- **Null group key**: the Splunk searches group by `target_user` and emit a null-valued
  row for events whose account did not resolve (e.g. `authentication failure` lines
  with `rhost=` but no `user=`). `SshRuleBase.group_key` instead skips those events -
  verified live: that exact case produced a second, meaningless "distributed brute
  force on (null)" alert. Set `allow_missing_group_key: true` for Splunk-identical
  behaviour.
- **Allowlist**: rules 03 and 04 filter on `must_not exists allow_reason`, which is the
  ELK equivalent of the Splunk `` `ssh_allowlist_filter(src_ip)` `` macro; rules 01/02
  have no allowlist, exactly as their Splunk searches.
- **Threat intel**: the app's Splunk lookups hold CIDR strings in the key column, so
  SPAMHAUS_DROP can never match an exact-key lookup there. ELK matches it correctly via
  the enrich processor's `ip_range` condition.
- **Alerting action**: rules use the console `debug` alerter so the port stays
  self-contained; swap/add `email`, `slack` or `jira` in any rule to route alerts.
