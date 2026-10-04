# Windows Brute Force Detection & Investigation

## Overview

This project demonstrates the detection and investigation of repeated failed Windows authentication attempts using Windows Security Event Logs and Splunk.

The scenario was performed in a controlled Windows 10 lab environment using a dedicated test account. Windows Security Event ID 4625 was used as the primary telemetry source for detecting failed authentication attempts.

The investigation covers:

- Attack simulation
- Windows security telemetry
- Splunk log ingestion
- SPL-based detection
- Alert creation and validation
- Security event investigation
- Authentication timeline analysis
- Successful-login correlation
- MITRE ATT&CK mapping
- Severity assessment
- False-positive analysis
- Recommended response actions
- Investigation evidence and screenshots

---

## Objective

The objective of this scenario is to identify a potential brute-force or password-guessing pattern by detecting multiple failed authentication attempts against the same account and source within a defined time window.

The investigation follows a SOC workflow:

Attack Simulation
→ Windows Security Event
→ Splunk Log Ingestion
→ Detection Query
→ Splunk Alert
→ Alert Validation
→ Investigation
→ Event Correlation
→ MITRE ATT&CK Mapping
→ Severity Assessment
→ Recommended Response
→ Documentation

---

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows 10 |
| SIEM | Splunk Enterprise |
| Log Collection | Splunk Universal Forwarder |
| Windows Telemetry | Windows Security Event Logs |
| Endpoint Telemetry | Sysmon |
| Detection Platform | Splunk |
| Detection Language | SPL |
| Test Account | `Test1` |
| Attack Simulation | Controlled failed-login attempts |

---

## Lab Architecture

The scenario was performed using a controlled lab environment consisting of a Windows 10 endpoint and Splunk for centralized security event analysis.

```text
Windows 10 VM
     |
     | Windows Security Events
     |
     v
Splunk Universal Forwarder
     |
     v
Splunk Enterprise
     |
     +-- Log Analysis
     +-- SPL Detection
     +-- Alert Generation
