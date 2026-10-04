
# Windows Brute-Force Detection with Splunk

## Overview

This project demonstrates the detection and investigation of repeated failed Windows authentication attempts using Windows Security Event Logs and Splunk Enterprise.

A controlled password-guessing simulation was performed against a dedicated local Windows test account named `test1`. The failed authentication attempts generated Windows Security Event ID 4625 and were collected and analyzed in Splunk.

A custom SPL detection rule was created to identify multiple failed authentication attempts against the same account and source within a five-minute time window. The detection identified 6 failed attempts and triggered a Splunk alert configured with Medium severity.

This project demonstrates the following SOC workflow:

**Security Event Generation → Log Collection → SIEM Ingestion → Detection → Alert → Investigation → Severity Assessment → Response Recommendation**

---

## Objectives

- Simulate controlled failed authentication attempts in a Windows 10 lab environment
- Generate Windows Security Event ID 4625
- Collect Windows Security logs in Splunk
- Analyze authentication failure events
- Develop an SPL-based brute-force detection rule
- Configure and validate a Splunk alert
- Investigate the detected activity
- Map the activity to MITRE ATT&CK
- Document findings and recommended SOC response actions

---

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Event Logs |
| Event ID | 4625 - Failed Logon |
| Test Account | `test1` |
| Source Address | `127.0.0.1` |
| Logon Type | 2 |
| Detection Window | 5 minutes |
| Detection Threshold | 5 or more failed attempts |
| Alert Severity | Medium |

The activity was performed in a controlled local lab environment.

---

## Test Account

A dedicated local Windows account named `test1` was created for the authentication-failure simulation.

The account was verified using:

```powershell
net user test1
````

The account was used only for controlled testing within the lab environment.

---

## Attack Simulation

Multiple incorrect passwords were entered for the `test1` account in the Windows 10 lab environment.

The failed authentication attempts generated Windows Security Event ID 4625 entries in Event Viewer.

The activity was performed locally from the Windows 10 VM and was used to generate controlled authentication-failure telemetry for detection testing.

---

## Windows Security Event ID 4625

Windows Security Event ID 4625 represents a failed logon attempt.

The generated events were reviewed in:

**Event Viewer → Windows Logs → Security**

The Security log was filtered for Event ID `4625`.

Multiple Audit Failure events were observed within a short period.

Relevant information included:

- Account Name: `test1`
- Logon Type: `2`
- Event ID: `4625`
- Failure information
- Timestamp
- Computer name

The observed source address for the local authentication attempts was:
```
127.0.0.1
```

---

## Splunk Log Ingestion

The Windows Security events were collected and ingested into Splunk Enterprise.

The initial search used was:
```
index=* EventCode=4625
```

The search returned multiple Windows Event ID 4625 records.

Relevant fields observed in Splunk included:

- `Account_Name`
- `Account_Domain`
- `Logon_Type`
- `Source_Network_Address`
- `Workstation_Name`
- `Failure_Reason`
- `EventCode`
- `ComputerName`

The observed authentication activity involved:
```
Account: test1
Source: 127.0.0.1
Logon Type: 2
EventCode: 4625
```

---

## Detection Logic

The detection was designed to identify repeated failed authentication attempts against the same account and source within a five-minute window.

The detection threshold was set to:

**5 or more failed attempts within 5 minutes.**

This helps identify potential brute-force or password-guessing patterns.

---

## SPL Detection Query
```
index=* EventCode=4625
| bin _time span=5m
| stats count as failed_attempts by _time, Account_Name, Source_Network_Address
| where failed_attempts >= 5
```

### Query Explanation

1. Searches for Windows Event ID 4625.
2. Groups events into five-minute windows.
3. Counts failed authentication attempts.
4. Groups the activity by time, account, and source.
5. Returns activity when five or more failed attempts are detected.

The detection identified:
```
Account: test1
Source: 127.0.0.1
Failed Attempts: 6
Time Window: 5 minutes
```

---

## Splunk Alert

The detection search was configured as a scheduled Splunk alert.

| Setting             | Value                     |
| ------------------- | ------------------------- |
| Alert Name          | Brute Force Detection     |
| Alert Type          | Scheduled                 |
| Severity            | Medium                    |
| Detection Threshold | 5 or more failed attempts |
| Detection Window    | 5 minutes                 |

The alert was successfully triggered after the simulated authentication failures met the detection condition.

---

## Investigation

The alert was investigated by reviewing the associated Windows Security events and Splunk fields.

### Observed Activity

| Field            | Value       |
| ---------------- | ----------- |
| Account          | `test1`     |
| Event ID         | `4625`      |
| Source Address   | `127.0.0.1` |
| Logon Type       | `2`         |
| Failed Attempts  | `6`         |
| Detection Window | `5 minutes` |
| Alert Severity   | Medium      |

The repeated Event ID 4625 events exceeded the configured detection threshold.

Because the source address was `127.0.0.1` and the activity was intentionally generated in the lab, this was classified as controlled test activity rather than a real security incident.

---

## MITRE ATT&CK Mapping

### T1110 - Brute Force

The simulated activity maps to MITRE ATT&CK technique **T1110 - Brute Force** because multiple authentication attempts were performed against a user account using incorrect credentials.

---

## Severity Assessment

### Medium

The Splunk alert was configured with Medium severity because repeated authentication failures were detected against the same account within a short time period.

In a production SOC environment, severity would depend on additional context such as:

- Account privilege level
- Source reputation
- Whether multiple accounts were targeted
- Whether a successful authentication followed the failures
- Whether the source was expected
- Whether additional suspicious activity was observed

For this project, the activity was a controlled lab simulation.

---

## Recommended SOC Response

If this detection occurred in a production environment, a SOC analyst should:

1. Validate the alert.
2. Identify the affected account.
3. Identify and investigate the source.
4. Review the authentication failure details.
5. Check for successful authentication following the failed attempts.
6. Check whether other accounts were targeted.
7. Review related activity from the source host.
8. Determine whether the activity is legitimate, suspicious, or malicious.
9. Escalate if compromise is suspected or confirmed.
10. Follow the organization's incident-response procedures.

---

## False Positives

Possible false positives include:

- Users repeatedly entering incorrect passwords
- Expired passwords
- Misconfigured applications
- Services using outdated credentials
- Legitimate administrative activity

The surrounding context should be reviewed before classifying the activity as malicious.

---

## Screenshots

**1. Lab Environment
2. Test Account
3. Failed Login Simulation
4. Windows Event ID 4625 Events
5. Event ID 4625 Details
6. Splunk Event ID 4625 Events
7. Brute-Force Detection
8. Splunk Alert**


## Key Findings

- Controlled failed authentication attempts were generated against the `test1` account.
- Windows generated Event ID 4625 security events.
- The events were successfully ingested into Splunk.
- The authentication events were analyzed using relevant Splunk fields.
- An SPL detection rule was created using a five-minute time window.
- The detection identified 6 failed authentication attempts.
- The configured threshold was 5 attempts.
- The Splunk alert was successfully triggered.
- The alert was configured with Medium severity.
- The activity was mapped to MITRE ATT&CK T1110 - Brute Force.

---

## Conclusion

This project demonstrates a practical SOC use case for detecting repeated Windows authentication failures using Splunk.

The lab covered the workflow from generating Windows security telemetry to creating an SPL detection, triggering an alert, investigating the associated events, assessing severity, mapping the activity to MITRE ATT&CK, and recommending appropriate SOC response actions.

This project provided hands-on experience with:

- Windows Security Event Logs
- Event ID 4625 analysis
- Splunk Enterprise
- SPL query development
- Security alert creation
- Alert investigation
- Authentication event analysis
- Brute-force detection
- MITRE ATT&CK mapping
- SOC investigation workflow
