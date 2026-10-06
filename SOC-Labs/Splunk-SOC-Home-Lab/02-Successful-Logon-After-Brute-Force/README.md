# Brute Force Followed by Successful Logon Detection with Splunk

## Overview

This project demonstrates the detection and investigation of a successful Windows logon occurring after multiple failed authentication attempts using Windows Security Event Logs and Splunk Enterprise.

A controlled authentication simulation was performed in a Windows 10 lab environment. Multiple failed logon attempts generated Windows Security Event ID 4625, followed by successful authentication activity generating Event ID 4624.

A custom SPL correlation query was developed to identify accounts with multiple failed authentication attempts followed by one or more successful logons within a five-minute time window.

The detection identified the `test1` account with 4 failed authentication attempts and 1 successful logon within the detection window. A Splunk alert named **Brute Force Followed by Successful Logon** was configured with High severity and successfully triggered.

This project demonstrates the following SOC workflow:

**Failed Authentication → Successful Authentication → Event Correlation → Detection → Alert → Investigation → Severity Assessment → Response Recommendation**

---

## Objectives

- Generate controlled Windows failed authentication events
- Generate successful Windows authentication events
- Analyze Windows Security Event ID 4625
- Analyze Windows Security Event ID 4624
- Search authentication activity in Splunk
- Correlate failed and successful logon events
- Develop an SPL-based detection rule
- Configure and validate a Splunk alert
- Investigate the detected authentication sequence
- Map the activity to MITRE ATT&CK
- Document findings and recommended SOC response actions

---

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 |
| SIEM | Splunk Enterprise 10.0.0 |
| Log Source | Windows Security Event Logs |
| Failed Logon Event | 4625 |
| Successful Logon Event | 4624 |
| Test Account | `test1` |
| Source Address | `127.0.0.1` |
| Detection Window | 5 minutes |
| Failed Attempt Threshold | 3 or more |
| Alert Name | Brute Force Followed by Successful Logon |
| Alert Severity | High |

The activity was performed in a controlled local lab environment.

---

## Attack Simulation

Multiple incorrect passwords were entered during the controlled authentication test in the Windows 10 lab environment.

The failed authentication attempts generated Windows Security Event ID `4625`.

A successful authentication was then performed, generating Windows Security Event ID `4624`.

The purpose of the simulation was to create an authentication sequence that could be correlated in Splunk:

**Multiple Failed Logons → Successful Logon**

The activity was performed only within the controlled lab environment.

---

## Windows Security Event ID 4625

Windows Security Event ID `4625` represents a failed logon attempt.

The generated events were reviewed in:

**Event Viewer → Windows Logs → Security**

The Security log was filtered for Event ID `4625`.

Multiple Audit Failure events were observed.

The observed Event ID 4625 activity included authentication failure information such as:

- Event ID: `4625`
- Logon Type
- Account information
- Timestamp
- Computer name
- Authentication failure details

The Event Viewer screenshot shows multiple Event ID 4625 Audit Failure events generated during the authentication simulation.

---

## Windows Security Event ID 4624

Windows Security Event ID `4624` represents a successful logon.

The Security log was filtered for Event ID `4624` to identify successful authentication activity.

The Event Viewer results showed multiple Audit Success events with Event ID `4624`.

The selected event demonstrated:

- Event ID: `4624`
- Task Category: Logon
- Keywords: Audit Success
- Logon Type: `2`
- Computer information
- Successful logon information

The Event Viewer evidence was used to verify that successful authentication events were being generated and recorded by Windows.

---

## Splunk Log Ingestion

The Windows Security events were collected and ingested into Splunk Enterprise.

The initial search used to identify successful logon events was:

```spl
index=* EventCode=4624

The search returned Windows Event ID 4624 records.
Relevant fields observed in Splunk included:
- Account_Name
- Logon_Type
- Source_Network_Address
- Workstation_Name
- ComputerName
- EventCode
The Splunk results showed successful authentication activity including the test1 account with:
Account: test1
Logon Type: 2
Source: 127.0.0.1
EventCode: 4624

Authentication Event Correlation
The next step was to correlate failed authentication events (4625) with successful authentication events (4624).
The following search was used to retrieve both event types:
**index=* (EventCode=4625 OR EventCode=4624)**

The authentication activity was then grouped into five-minute windows and analyzed by account.
The goal was to identify a pattern where:
Multiple 4625 Failed Logons
              ↓
       4624 Successful Logon

This type of sequence can be important in a SOC because repeated authentication failures followed by a successful authentication may indicate that an account password was eventually guessed or otherwise compromised.
However, the presence of this sequence alone does not prove account compromise. Additional investigation and contextual analysis are required.
Detection Logic
The detection was designed to identify accounts that experienced multiple failed authentication attempts followed by successful authentication within the same five-minute window.
The detection threshold was:
3 or more failed attempts and at least 1 successful logon within 5 minutes.
This detection helps identify authentication patterns that may require further investigation.
SPL Detection Query
**index=* (EventCode=4625 OR EventCode=4624)
| bin _time span=5m
| stats
    count(eval(EventCode=4625)) as failed_attempts
    count(eval(EventCode=4624)) as successful_logons
    by _time, Account_Name
| where failed_attempts >= 3 AND successful_logons >= 1
**
Query Explanation
1. Searches for Windows Event ID 4625 and 4624.
2. Groups authentication events into five-minute windows.
3. Counts failed authentication attempts.
4. Counts successful authentication events.
5. Groups the results by time and account.
6. Returns accounts with at least 3 failed attempts and at least 1 successful logon.
The detection result observed in Splunk included:
Account: test1
Failed Attempts: 4
Successful Logons: 1
Time Window: 5 minutes

Detection Result
The Splunk correlation search successfully identified the authentication sequence involving the test1 account.
The observed result was:
Field	Value
Account	test1
Failed Attempts	4
Successful Logons	1
Detection Window	5 minutes


The detection demonstrated that failed and successful authentication events could be correlated using SPL.
Splunk Alert
The correlation search was configured as a scheduled Splunk alert.
Setting	Value
Alert Name	Brute Force Followed by Successful Logon
Alert Type	Scheduled
Severity	High
Failed Attempt Threshold	3 or more
Successful Logon Threshold	1 or more
Detection Window	5 minutes


The alert was successfully triggered after the authentication activity met the detection conditions.
The triggered alert is visible in the Splunk Triggered Alerts interface.
Investigation
The alert was investigated by reviewing the associated Windows Security events and Splunk correlation results.
Observed Activity
The Splunk correlation result identified:
Account: test1
Failed Attempts: 4
Successful Logons: 1
Detection Window: 5 minutes

The sequence indicates that multiple failed authentication attempts occurred within the detection window and were followed by a successful authentication event.
The observed source address for the test1 authentication activity in Splunk was:
127.0.0.1

The activity was intentionally generated within the local Windows lab environment.
Therefore, the activity was classified as controlled test activity rather than a real security incident.

Investigation Workflow
If the same detection occurred in a production SOC environment, an analyst should investigate:
1. Identify the affected account.
2. Review the number and timing of failed authentication attempts.
3. Identify the source IP address or host.
4. Review the successful authentication event.
5. Determine the authentication method and logon type.
6. Determine whether the successful login was expected.
7. Check whether other accounts were targeted.
8. Review additional activity from the source host.
9. Check for suspicious activity after the successful authentication.
10. Determine whether the activity represents legitimate behavior or possible account compromise.
11. Escalate the incident if compromise is suspected or confirmed.
12. Follow the organization's incident-response procedures.

MITRE ATT&CK Mapping
T1110 - Brute Force
The failed authentication activity maps to MITRE ATT&CK technique T1110 - Brute Force because multiple authentication attempts were performed against an account.
The successful authentication following repeated failures is treated as an investigation signal rather than automatically being classified as proof of compromise.
Severity Assessment
High

The Splunk alert was configured with High severity because multiple failed authentication attempts were followed by a successful authentication within a short time window.
In a production SOC environment, the final severity should depend on additional context such as:
- Account privilege level
- Source IP reputation
- Whether the source is internal or external
- Whether the login was expected
- Whether multiple accounts were targeted
- Whether the account owner confirmed the activity
- Whether suspicious activity occurred after authentication
- Whether additional indicators of compromise were present

For this project, the activity was intentionally generated in a controlled lab environment.
Recommended SOC Response
If this detection occurred in a production environment, a SOC analyst should:
1. Validate the alert.
2. Identify the affected account.
3. Investigate the source address and host.
4. Review the failed authentication events.
5. Review the successful authentication event.
6. Determine whether the successful login was legitimate.
7. Check for additional suspicious activity after authentication.
8. Check whether other accounts were targeted.
9. If compromise is suspected, follow account containment procedures.
10. Escalate the incident according to organizational incident-response procedures.
Possible containment actions in an actual incident may include disabling or locking the affected account, resetting credentials, terminating suspicious sessions, and investigating the source host, depending on organizational procedures and evidence.
False Positives
Possible false positives include:
- Users repeatedly entering incorrect passwords
- Users forgetting recently changed passwords
- Legitimate users successfully authenticating after several failed attempts
- Misconfigured applications
- Services using outdated credentials
- Administrative activity
The authentication sequence should always be investigated in context before determining that an account has been compromised.
Screenshots
1. Windows Event ID 4624
 
2. Event ID 4624 Details
 
3. Windows Event ID 4625 Events
 
4. Splunk Event ID 4624 Events
 
5. Successful Logon Correlation
 
6. Splunk Triggered Alert
 
Key Findings
- Windows generated Event ID 4625 Audit Failure events during the controlled authentication simulation.
- Windows generated Event ID 4624 Audit Success events.
- The authentication events were successfully ingested into Splunk.
- Splunk successfully identified Windows Event ID 4624 records.
- Failed and successful authentication events were correlated using SPL.
- The test1 account was identified with 4 failed authentication attempts and 1 successful logon within a five-minute window.
- A correlation-based detection rule was created.
- The Splunk alert Brute Force Followed by Successful Logon was successfully triggered.
- The alert was configured with High severity.
- The failed authentication activity was mapped to MITRE ATT&CK T1110 - Brute Force.
- The activity was intentionally generated in the controlled lab environment and was not a real security incident.

Conclusion
This project demonstrates a practical SOC detection and investigation workflow for identifying a successful Windows authentication following multiple failed authentication attempts.
The lab covered Windows Security Event ID 4625 analysis, Event ID 4624 analysis, Splunk log ingestion, authentication event correlation, SPL detection development, alert creation, alert investigation, severity assessment, and MITRE ATT&CK mapping.
The project provided hands-on experience with:
- Windows Security Event Logs
- Event ID 4625 analysis
- Event ID 4624 analysis
- Splunk Enterprise
- SPL query development
- Authentication event correlation
- Security alert creation
- Alert investigation
- Brute-force detection
- MITRE ATT&CK mapping
- SOC investigation workflow
