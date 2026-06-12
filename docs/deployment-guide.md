# Deployment Guide

## Prerequisites

- Splunk Enterprise 8.x+ or Splunk Cloud
- Splunk Universal Forwarder on Linux servers generating SSH logs
- Geo-IP lookup installed (Settings > Lookups > Lookup Table Files > `GeoIP-City.mmdb`)
- Access to `$SPLUNK_HOME/etc/system/local/` on indexers/search heads

## Step 1: Onboard SSH Logs

### On the Universal Forwarder

Copy `data-onboarding/inputs.conf` to the forwarder:

```bash
scp data-onboarding/inputs.conf user@forwarder:/opt/splunkforwarder/etc/system/local/
```

Restart the forwarder:

```bash
/opt/splunkforwarder/bin/splunk restart
```

Verify log ingestion:

```bash
/opt/splunkforwarder/bin/splunk search "index=linux_secure | stats count"
```

### On the Indexer / Search Head

Copy `data-onboarding/props.conf` and `data-onboarding/transforms.conf`:

```bash
cp data-onboarding/props.conf $SPLUNK_HOME/etc/system/local/
cp data-onboarding/transforms.conf $SPLUNK_HOME/etc/system/local/
```

Restart Splunk:

```bash
$SPLUNK_HOME/bin/splunk restart
```

## Step 2: Install Geo-IP Lookup

1. Go to **Settings > Lookups > Lookup Table Files**
2. Click **Add New**
3. Upload the GeoIP-City.mmdb file
4. Destination filename: `geoip`
5. Create a lookup definition:
   - **Name:** `geoip`
   - **Type:** `Geographic IP`
   - **File:** `geoip`
   - Fields: `lat`, `lon`, `city`, `country`

## Step 3: Import Lookup Tables

1. Go to **Settings > Lookups > Lookup Table Files**
2. Click **Add New** for each file:
   - `lookups/known-attackers.csv`
   - `lookups/ssh-policy-violations.csv`
3. Go to **Lookup Definitions** and create definitions pointing to each file

## Step 4: Import Dashboards

### Via Splunk Web:

1. Go to **Apps > Search & Reporting > Dashboards**
2. Click **Create New Dashboard**
3. Give it a title (e.g., "SSH Threat Detection")
4. Click **Dashboard Source > Edit Source**
5. Paste content from `dashboards/ssh-threat-dashboard.xml`
6. Repeat for `dashboards/ssh-monitoring-dashboard.xml`

### Via REST API:

```bash
curl -k -u admin:password \
  -X POST https://localhost:8089/servicesNS/admin/search/data/ui/views \
  -d "name=ssh_threat_dashboard" \
  -d "eai:data=$(cat dashboards/ssh-threat-dashboard.xml)"
```

## Step 5: Install Macros

1. Go to **Settings > Advanced Search > Search Macros**
2. Click **Add New** for each macro in `macros/ssh-log-parser.conf` and `macros/ssh-threat-intel.conf`

Or copy the macros.conf to the search head:

```bash
cp macros/ssh-log-parser.conf $SPLUNK_HOME/etc/system/local/macros.conf
$SPLUNK_HOME/bin/splunk restart
```

## Step 6: Create Alerts

1. Go to **Settings > Searches > Saved Searches**
2. Click **Create New Saved Search**
3. Configure the search from `alerts/brute-force-alert.spl`
4. Configure alert actions (email, Slack, webhook)
5. Repeat for `alerts/credential-stuffing-alert.spl`

### Slack Integration:

1. Go to **Settings > Alert Actions > Slack Settings**
2. Configure webhook URL from Slack Apps
3. Reference `#security-alerts` channel in alert definitions

## Step 7: Verify Detection

Use the sample log data to verify everything works:

```bash
# Generate sample logs
python scripts/generate-sample-logs.py

# Upload to Splunk for testing
$SPLUNK_HOME/bin/splunk add oneshot ./output/auth.log -index linux_secure -sourcetype linux_secure
```

Then check:

- [ ] SSH Threat Dashboard shows data
- [ ] SSH Operations Dashboard renders correctly
- [ ] Geo-IP data populates on threat map
- [ ] Brute force queries return results
- [ ] Alerts fire when thresholds are crossed

## Production Considerations

| Consideration | Recommendation |
|--------------|----------------|
| **Log Volume** | Tune `count >= N` thresholds based on baseline traffic |
| **False Positives** | Add exceptions for known admin IPs, CI/CD runners |
| **Performance** | Use summary indexing for long-range queries |
| **Retention** | Set 90-day retention for SSH indexes |
| **Compliance** | Enable audit logging for all saved searches |
| **Scaling** | Use indexer clustering for high-volume environments |
