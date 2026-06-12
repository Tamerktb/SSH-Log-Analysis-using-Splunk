# SSH Log Analysis using Splunk

Enterprise-grade Splunk SIEM solution for detecting SSH-based threats — brute force attacks, credential stuffing, anomaly detection, and policy violations — with pre-built dashboards, correlation searches, and automated alerts.

![Architecture](https://github.com/Tamerktb/SSH-Log-Analysis-using-Splunk/blob/main/df3ul9s9oiv.jpg?raw=true)

## Features

| Capability | Description |
|------------|-------------|
| **Brute Force Detection** | Identifies SSH brute force patterns using failed login thresholds, time-based correlation, and source IP tracking |
| **Credential Stuffing Detection** | Detects distributed credential attacks across multiple user accounts from single/multiple sources |
| **Anomaly Detection** | Baselining normal SSH behavior and flagging deviations — off-hours logins, impossible travel, new geolocations |
| **Geo-IP Threat Intelligence** | Enriches SSH events with Geo-IP data and scores source IPs against known threat feeds |
| **User Behavior Analytics** | Tracks login patterns per user — first-time logins, privilege escalation, concurrent sessions |
| **Real-time Alerts** | Automated correlation searches with email/Slack/webhook notifications for critical threats |
| **Operational Dashboards** | Real-time SSH monitoring, failed login heatmaps, geographic threat maps, trend analysis |

## Repository Structure

```
├── spl-queries/                  # SPL queries organized by detection category
│   ├── brute-force-detection.spl
│   ├── credential-stuffing.spl
│   ├── anomaly-detection.spl
│   ├── geo-ip-analysis.spl
│   └── user-behavior.spl
├── dashboards/                   # Splunk dashboard XML definitions
│   ├── ssh-threat-dashboard.xml
│   └── ssh-monitoring-dashboard.xml
├── alerts/                       # Saved search / alert definitions
│   ├── brute-force-alert.spl
│   └── credential-stuffing-alert.spl
├── macros/                       # Splunk macro definitions
│   ├── ssh-log-parser.conf
│   └── ssh-threat-intel.conf
├── lookups/                      # CSV lookup files for enrichment
│   ├── known-attackers.csv
│   └── ssh-policy-violations.csv
├── data-onboarding/              # Splunk forwarder / heavy forwarder configs
│   ├── inputs.conf
│   ├── props.conf
│   └── transforms.conf
├── sample-data/                  # Sample log data for testing
│   ├── auth.log.sample
│   └── secure.log.sample
├── scripts/                      # Automation and data generation
│   └── generate-sample-logs.py
└── docs/                         # Documentation
    ├── deployment-guide.md
    └── detection-rules.md
```

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/Tamerktb/SSH-Log-Analysis-using-Splunk.git
cd SSH-Log-Analysis-using-Splunk

# 2. Generate sample SSH logs for testing
python scripts/generate-sample-logs.py

# 3. Follow the deployment guide
cat docs/deployment-guide.md
```

### Deploy to Splunk

1. **Onboard SSH logs** — copy `data-onboarding/` configs to your Splunk heavy forwarder or UF:
   ```
   $SPLUNK_HOME/etc/system/local/inputs.conf
   $SPLUNK_HOME/etc/system/local/props.conf
   $SPLUNK_HOME/etc/system/local/transforms.conf
   ```

2. **Upload lookups** — go to Settings > Lookups > Lookup Table Files, upload `lookups/*.csv`

3. **Import dashboards** — go to Apps > Search & Reporting > Dashboards, create new and paste XML from `dashboards/`

4. **Create alerts** — go to Settings > Searches > Saved Searches, create new from `alerts/*.spl`

## Detection Coverage

### MITRE ATT&CK Mappings

| Technique | ID | Detection |
|-----------|-----|-----------|
| Brute Force | T1110 | `spl-queries/brute-force-detection.spl` |
| Credential Stuffing | T1110.004 | `spl-queries/credential-stuffing.spl` |
| Valid Accounts | T1078 | `spl-queries/user-behavior.spl` |
| Unusual Login Activity | T1078.002 | `spl-queries/anomaly-detection.spl` |

### Alert Severity Levels

| Severity | Threshold | Action |
|----------|-----------|--------|
| Low | 3-5 failed attempts in 5min | Dashboard highlight |
| Medium | 10-20 failed attempts in 5min | Email alert to SOC |
| High | 20+ failed attempts or confirmed success | Slack/PagerDuty notification |

## Sample SPL Query

```spl
index=linux_secure sourcetype=linux_secure "Failed password"
| stats count by src_ip, user, _time
| where count > 5
| lookup geoip src_ip OUTPUT city, country, lat, lon
| eval threat_score = count * 10
| sort - count
| table _time, src_ip, user, count, city, country, threat_score
```

## Deployment Options

| Environment | Approach |
|-------------|----------|
| **Splunk Cloud** | Upload configs via Deployment Server or API |
| **Splunk Enterprise** | Copy configs to `$SPLUNK_HOME/etc/system/local/` |
| **Docker Splunk** | Mount configs as volumes |
| **Universal Forwarder** | Deploy `inputs.conf` to forwarder, rest to indexer/search head |

## Author

**Tamer Alkhatib** — Cybersecurity Engineer & SOC Analyst

[![LinkedIn](https://img.shields.io/badge/-LinkedIn-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/tamer-al-khatib/)
[![GitHub](https://img.shields.io/badge/-GitHub-181717?style=flat&logo=github&logoColor=white)](https://github.com/Tamerktb)

## License

MIT
