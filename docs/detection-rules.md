# Detection Rules

## Rule Matrix

### Brute Force Detection

| Rule ID | Name | Severity | MITRE ATT&CK | Threshold | Response |
|---------|------|----------|--------------|-----------|----------|
| SSH-BF-001 | Basic Brute Force | Medium | T1110 | 5+ failed attempts in 5min | Dashboard alert |
| SSH-BF-002 | Advanced Brute Force | High | T1110 | 10+ failed attempts in 5min | Email to SOC |
| SSH-BF-003 | Targeted Account Attack | High | T1110 | 3+ failed on root/admin in 5min | Email + Slack |
| SSH-BF-004 | Distributed Brute Force | High | T1110 | 5+ unique users from single IP in 10min | Slack alert |
| SSH-BF-005 | Successful Brute Force | Critical | T1110 | Successful login after 5+ failures | PagerDuty |

### Credential Stuffing Detection

| Rule ID | Name | Severity | MITRE ATT&CK | Threshold | Response |
|---------|------|----------|--------------|-----------|----------|
| SSH-CS-001 | Multi-Account Stuffing | Critical | T1110.004 | 10+ unique users from single IP in 2min | Slack + Email |
| SSH-CS-002 | Distributed Stuffing | Critical | T1110.004 | 3+ sources targeting same user in 5min | PagerDuty |
| SSH-CS-003 | Slow Credential Stuffing | Medium | T1110.004 | 3-9 attempts/hour for 6+ hours | Dashboard alert |
| SSH-CS-004 | Cross-Protocol Stuffing | High | T1110.004 | Same IP hitting 2+ services | Email alert |

### Anomaly Detection

| Rule ID | Name | Severity | MITRE ATT&CK | Threshold | Response |
|---------|------|----------|--------------|-----------|----------|
| SSH-AN-001 | Impossible Travel | Critical | T1078.002 | Same user in 2+ cities within 1h | PagerDuty |
| SSH-AN-002 | Off-Hours Login | Medium | T1078 | Login outside 7am-7pm or weekends | Dashboard alert |
| SSH-AN-003 | First-Time Login | Medium | T1078 | User from never-before-seen IP | Email alert |
| SSH-AN-004 | Concurrent Sessions | High | T1078 | 3+ simultaneous sessions per user | Slack alert |
| SSH-AN-005 | Statistical Outlier | Medium | T1110 | 3+ stddev above baseline | Dashboard alert |

### User Behavior Analytics

| Rule ID | Name | Severity | MITRE ATT&CK | Threshold | Response |
|---------|------|----------|--------------|-----------|----------|
| SSH-UB-001 | Login Volume Anomaly | Medium | T1078 | 2+ stddev above user baseline | Dashboard alert |
| SSH-UB-002 | Privilege Escalation | High | T1078 | Direct root/admin SSH login | Email alert |
| SSH-UB-003 | Account Sharing | Medium | T1078 | 3+ users from same IP in 15min | Dashboard alert |
| SSH-UB-004 | Session Duration Anomaly | Medium | T1078 | Session <30s or >8h | Dashboard alert |
| SSH-UB-005 | Lateral Movement | Critical | T1078 | Privileged user on 3+ hosts in 30min | PagerDuty |

### Geo-IP Intelligence

| Rule ID | Name | Severity | Threshold | Response |
|---------|------|----------|-----------|----------|
| SSH-GEO-001 | Tor/Proxy Login | Medium | Anonymous proxy detected | Dashboard alert |
| SSH-GEO-002 | High-Risk Country | Medium | Login from high-risk country | Email alert |
| SSH-GEO-003 | Known Attacker IP | High | IP in threat intel feed | Slack alert |
| SSH-GEO-004 | Geographic Anomaly | High | User from new country | Email alert |

## Alert Response Playbook

### Brute Force (SSH-BF-002 / SSH-BF-003)

1. **Triage:** Verify source IP is not a known admin/VPN/CI/CD IP
2. **Contain:** Block source IP at firewall level:
   ```bash
   iptables -A INPUT -s $SOURCE_IP -j DROP
   ```
3. **Investigate:** Check if any successful logins occurred during attack window
4. **Remediate:** If breach confirmed, rotate compromised credentials immediately
5. **Report:** Document in incident tracker with Splunk search ID

### Credential Stuffing (SSH-CS-001)

1. **Triage:** Verify IP is not a corporate NAT gateway
2. **Contain:** Rate-limit or block IP at perimeter
3. **Investigate:** Identify which accounts were targeted successfully
4. **Remediate:** Force password reset for all targeted accounts
5. **Escalate:** Notify security team if sensitive accounts affected

### Successful Brute Force (SSH-BF-005)

1. **Triage:** Confirm the successful login event
2. **Immediate Containment:**
   - Disable compromised user account
   - Revoke SSH keys associated with account
   - Block source IP
3. **Investigation:**
   - Review all commands executed during session (auditd/sudo logs)
   - Check for data exfiltration patterns
   - Check for persistence mechanisms (new SSH keys, cron jobs)
4. **Remediation:**
   - Rotate all credentials on compromised host
   - Scan for backdoors
   - Review and tighten SSH configuration
5. **Post-Incident:** Update detection rules based on TTPs observed

## Tuning Guidelines

### Reducing False Positives

1. **Exclude known infrastructure:**
   ```spl
   | search NOT src_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   ```

2. **Exclude CI/CD runners:**
   ```spl
   | search NOT src_ip=10.0.0.200
   ```

3. **Adjust thresholds based on baseline:**
   - Use `eventstats avg(count)` to dynamically set thresholds
   - Increase thresholds for high-traffic servers

4. **Create allowlist lookup:**
   ```csv
   src_ip,reason
   10.0.0.0/8,Internal Network
   192.168.0.0/16,Corporate LAN
   ```

### Severity Adjustment

```spl
| eval severity = case(
    known_threat == "YES" AND count >= 20, "CRITICAL",
    known_threat == "YES", "HIGH",
    is_anonymous_proxy == true, "HIGH",
    count >= 50, "HIGH",
    count >= 20, "MEDIUM",
    count >= 5, "LOW"
  )
```
