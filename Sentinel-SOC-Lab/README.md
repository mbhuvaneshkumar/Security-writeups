# Microsoft Sentinel SOC Home Lab

## Windows Security Monitoring, Detection and Incident Investigation

## 1. Project Overview

This project demonstrates a hands-on Security Operations Center (SOC) home lab built using **Microsoft Sentinel**, **Microsoft Azure**, and a Windows virtual machine.

The objective was to configure centralized Windows security event monitoring, collect security logs using Azure Monitor Agent (AMA), create a detection rule for repeated failed logon attempts, generate a Sentinel incident, and investigate the related authentication events.

This lab helped me understand how a SOC analyst can monitor endpoint activity, identify suspicious authentication patterns, review alerts, and investigate security incidents using Microsoft Sentinel.

## 2. Lab Architecture

The lab uses the following components:

- **Microsoft Azure:** Cloud environment hosting the lab resources.
- **Microsoft Sentinel:** SIEM platform for security monitoring, detection, and incident investigation.
- **Log Analytics Workspace:** Central location for collecting and querying security logs.
- **Windows Virtual Machine:** Endpoint generating Windows security events.
- **Azure Monitor Agent (AMA):** Collects Windows security events from the VM.
- **Data Collection Rule (DCR):** Configures which Windows events are collected and where they are sent.
- **Kusto Query Language (KQL):** Used to query and investigate security events.

### Architecture Flow

Windows VM → Azure Monitor Agent → Data Collection Rule → Log Analytics Workspace → Microsoft Sentinel → Analytics Rule → Alert and Incident Investigation

## 3. Tools and Technologies

| Tool / Technology | Purpose |
|---|---|
| Microsoft Sentinel | SIEM monitoring and incident investigation |
| Microsoft Azure | Cloud infrastructure |
| Windows Virtual Machine | Endpoint log generation |
| Azure Monitor Agent | Security event collection |
| Data Collection Rule | Log collection configuration |
| Log Analytics Workspace | Centralized log storage and querying |
| KQL | Security log analysis |
| Windows Event Viewer | Windows event verification |
| Remote Desktop (RDP) | VM access |

## 4. Project Implementation

### Phase 1: Microsoft Sentinel Environment Setup

- Created an Azure resource group.
- Created a Log Analytics workspace.
- Enabled Microsoft Sentinel on the workspace.
- Prepared the environment for security monitoring.

### Phase 2: Windows Virtual Machine Setup

- Created a Windows virtual machine in Azure.
- Configured the required networking settings.
- Configured Remote Desktop access.
- Used the VM as the monitored endpoint.

### Phase 3: Remote Desktop Connection

- Connected to the Windows VM using Remote Desktop.
- Verified the VM hostname.
- Verified the logged-in Windows account.

### Phase 4: Windows Security Logging

- Configured Windows security auditing.
- Reviewed Windows Security logs.
- Verified that security events were being generated on the endpoint.

### Phase 5: Connect Windows VM to Microsoft Sentinel

- Installed and configured the Windows Security Events via AMA solution and connector.
- Created a Data Collection Rule.
- Associated the Windows VM with the DCR.
- Selected the Common Windows Security Events collection option.
- Sent collected events to the Log Analytics workspace.
- Verified incoming events using KQL.

**Example KQL query — Security Event Summary**

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize EventCount = count() by EventID
| order by EventCount desc
```

### Phase 6: Analytics Rule and Alert Generation

Created a scheduled analytics rule to detect repeated failed Windows logon attempts.

**Detection scenario:** Multiple failed Windows logons.

**Detection logic:**
- Monitored Windows Security Event ID 4625.
- Grouped failed logon events by account and computer.
- Used a five-minute time window.
- Triggered detection when at least five failed attempts occurred within a time bucket.
- Configured the rule to generate an incident.

**Detection KQL query**

```kql
SecurityEvent
| where TimeGenerated > ago(15m)
| where EventID == 4625
| summarize FailedAttempts = count(),
            FirstFailure = min(TimeGenerated),
            LastFailure = max(TimeGenerated)
    by Account, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| project TimeGenerated, Computer, Account, FailedAttempts, FirstFailure, LastFailure
| order by TimeGenerated desc
```

**Result:**

- Generated multiple failed logon events in the controlled lab.
- Observed six failed logon attempts for the test account `soclab\tester` within a five-minute window.
- Confirmed that the detection query identified the activity.
- Successfully generated a Microsoft Sentinel alert and incident with Medium severity.

### Phase 7: Incident Investigation

Investigated the generated Sentinel incident and reviewed the associated authentication events.

Activities performed:

- Opened the generated incident.
- Reviewed the alert details.
- Examined the analytics rule detection query.
- Reviewed the incident Attack story.
- Queried successful Windows logon events.
- Compared failed and successful logon events chronologically.
- Inspected the details of a successful logon event.

**Important Windows Event IDs**

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | Process creation |
| 4672 | Special privileges assigned to a new logon |
| 4674 | Operation attempted on a privileged object |
| 4702 | Scheduled task updated |

**Investigation findings:**

- Six failed logon events were observed for `soclab\tester`.
- A successful logon event (4624) was observed after the failed attempts.
- The successful logon used Logon Type 2, indicating an interactive logon.
- The event showed the source address `::1`, which is the IPv6 loopback address.
- This indicates local activity on the VM, not a confirmed external attacker connection.

The activity was generated as part of a controlled lab simulation. The findings demonstrate detection and investigation of repeated authentication failures, not proof of a real-world attack.

## 5. Key Learning Outcomes

Through this project, I gained practical experience with:

- Setting up Microsoft Sentinel in Azure.
- Configuring a Windows endpoint for security monitoring.
- Deploying Azure Monitor Agent.
- Creating and configuring Data Collection Rules.
- Collecting Windows Security Events.
- Querying security logs using KQL.
- Understanding Windows authentication event IDs.
- Creating scheduled analytics rules.
- Detecting repeated failed logon attempts.
- Generating and reviewing Sentinel incidents.
- Investigating authentication activity using event timelines.

## 6. Screenshots and Evidence

Screenshots documenting the implementation are available in the `Screenshots` directory.

The screenshots are organized by project phase:

- Phase 1 — Environment Setup
- Phase 2 — Virtual Machine Setup
- Phase 3 — Remote Desktop Connection
- Phase 4 — Windows Security Logging
- Phase 5 — Sentinel Integration and Log Collection
- Phase 6 — Analytics Rule and Alert Generation
- Phase 7 — Incident Investigation

## 7. Conclusion

This project provided hands-on experience with Microsoft Sentinel and the fundamental workflow of a SOC analyst.

I configured centralized Windows security event collection, created a scheduled detection rule for repeated failed logon attempts, generated a security incident, and investigated the related authentication events.

This lab strengthened my understanding of SIEM monitoring, security event analysis, KQL, alert generation, and basic incident investigation.

## 8. Disclaimer

This project was conducted in a personal Azure lab environment for educational purposes. Authentication events were generated intentionally for testing and detection validation. No unauthorized systems were targeted.

---

**Project:** Microsoft Sentinel SOC Home Lab  
**Focus:** SIEM | Windows Security Monitoring | KQL | Detection Engineering | Incident Investigation  
**Platform:** Microsoft Azure and Microsoft Sentinel
