<p align="center">
  <img
    src="https://github.com/user-attachments/assets/ddc67aca-d80d-4ba2-86ad-a1e3ab1c9d47"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>

---

## 🎭 Scenario Context

The server team observed a **significant network performance degradation** affecting several older devices within the internal **10.0.0.0/16** network. After ruling out external causes such as DDoS attacks, attention shifted to the possibility of **malicious or unauthorized internal activity**.

The security team was tasked with investigating whether any internal hosts were:

- Generating abnormal network traffic  
- Performing unauthorized discovery or scanning activity  
- Attempting lateral movement within the environment  

This scenario frames the hunt as an **internal threat and anomaly investigation**, focused on detecting compromised systems, unauthorized reconnaissance, or misuse of internal network resources.

---

# 🛡️ Threat Hunt Report – Sudden Network Slowdown & Internal Port Scanning

---

## 📌 Executive Summary

This threat hunt was initiated after a sudden network slowdown was observed within the environment. Investigation revealed that `vm-lab-mde` was generating a high volume of failed network connections, consistent with automated port scanning activity. Further analysis uncovered a PowerShell script (`portscan.ps1`) executing under the SYSTEM account, which initiated the scanning behavior. Although malware scans returned no detections, the abnormal execution context and behavior resulted in device isolation and reimaging to mitigate potential risk.

---

## 🎯 Hunt Objectives

- Identify the cause of abnormal network activity and connection failures  
- Determine whether the activity represented malicious discovery or lateral movement  
- Correlate behaviors to MITRE ATT&CK techniques  
- Contain and remediate any potentially compromised system  

---

## 🧭 Scope & Environment

- **Environment:** Azure-hosted Windows virtual machines  
- **Primary Host:** vm-lab-mde  
- **Data Sources:** Microsoft Defender for Endpoint  
  - DeviceNetworkEvents  
  - DeviceProcessEvents  
  - DeviceFileEvents  
- **Timeframe:** 2026-01-05  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)  
- [🧪 Preparation](#-preparation)  
- [📥 Data Collection](#-data-collection)  
- [🧠 Data Analysis](#-data-analysis)  
- [🔎 Investigation](#-investigation)  
  - [Step 1 – Identify Abnormal Network Failures](#step-1--identify-abnormal-network-failures)  
  - [Step 2 – Analyze Connection Patterns](#step-2--analyze-connection-patterns)  
  - [Step 3 – Process Correlation](#step-3--process-correlation)  
  - [Step 4 – File Origin Analysis](#step-4--file-origin-analysis)  
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)  
- [🚩 Flag Analysis](#-flag-analysis)  
- [🛡️ Response Actions](#-response-actions)  
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)  
- [🧾 Final Assessment](#-final-assessment)  
- [📎 Analyst Notes](#-analyst-notes)  

---

## 🧠 Hunt Overview

The hunt began after noticing performance degradation and abnormal network behavior. Initial telemetry showed that `vm-lab-mde` was failing a large number of outbound connection attempts. When reviewed chronologically, the failures followed sequential port patterns, strongly indicating active network service scanning.

Further investigation confirmed that a PowerShell script named `portscan.ps1` was executed around the time the scanning began. The script was created and executed under the SYSTEM account, which was not expected and had not been deployed by administrators. Although malware scans did not return detections, the behavior warranted containment and reimaging.

---

## 🧪 Preparation

### Goal
Determine whether abnormal internal network activity indicated malicious discovery or lateral movement attempts.

### Hypothesis
If a host is performing sequential failed connections across many ports, then it may be executing unauthorized discovery or reconnaissance tools.

---

## 📥 Data Collection

### Data Sources
- `DeviceNetworkEvents` – detect abnormal connection failures  
- `DeviceProcessEvents` – identify suspicious process execution  
- `DeviceFileEvents` – determine file origin and creator  

---

## 🧠 Data Analysis

### Focus Areas
- Volume and pattern of failed connections  
- Temporal correlation between network activity and process creation  
- Script origin and execution context  

---

## 🔎 Investigation

### Step 1 – Identify Abnormal Network Failures

`vm-lab-mde` was found generating large numbers of failed connection attempts.

~~~kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
~~~

<img width="975" height="291" alt="image" src="https://github.com/user-attachments/assets/4a02ef7b-dd2f-4978-84c4-6fb988850662" />

---

### Step 2 – Analyze Connection Patterns

Sequential failed connections were observed, consistent with automated port scanning.

~~~kql
let IPInQuestion = "10.0.0.143";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
~~~

<img width="109" height="559" alt="image" src="https://github.com/user-attachments/assets/ada38279-5291-4c64-964c-5d78f448dddb" />


**Finding:** Chronological review showed sequential port targeting, indicating active scanning.

---

### Step 3 – Process Correlation

Pivoted to process telemetry to determine what initiated the scanning.

~~~kql
let VMName = "vm-lab-mde";
let specificTime = datetime(2026-01-05T20:37:59.3585288Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
~~~

**Finding:** PowerShell script `portscan.ps1` executed at  
`2026-01-05T20:37:14.1934562Z`.

<img width="975" height="329" alt="image" src="https://github.com/user-attachments/assets/f5a99043-77a5-48cf-8efd-267f00a14659" />

---

### Step 4 – File Origin Analysis

Determined who created the script.

~~~kql
DeviceFileEvents
| where DeviceName == "vm-lab-mde"
| where ActionType == "FileCreated"
| where FileName contains "portscan"
| order by Timestamp desc
~~~

<img width="605" height="564" alt="image" src="https://github.com/user-attachments/assets/f5886cc3-8403-447d-8a87-d32023663a38" />

**Finding:**  
- File: `portscan.ps1`  
- Creator: SYSTEM  
- Creation Time: January 5, 2026 – 3:37 PM  

This behavior was not authorized or expected.

---

## 🧬 MITRE ATT&CK Summary

| Tactic | Technique | MITRE ID | Evidence |
|-------|------------|----------|----------|
| Discovery | Network Service Scanning | T1046 | Sequential failed connections across many ports |
| Execution | PowerShell | T1059.001 | `portscan.ps1` executed on host |
| Defense Evasion / Privilege Context | Valid Accounts: SYSTEM | T1078.003 | Script created and executed as SYSTEM |
| Lateral Movement (attempted) | Remote Services | T1021 | Scanning targeted local and peer systems |

---

## 🚩 Flag Analysis

🚩 **Flag 1 – Abnormal internal network failures**  
High volume of failed connections detected.

🚩 **Flag 2 – Sequential port scanning behavior**  
Chronological port patterns confirmed discovery activity.

🚩 **Flag 3 – Unauthorized PowerShell execution**  
`portscan.ps1` executed without administrative approval.

🚩 **Flag 4 – SYSTEM-level execution context**  
Script created and launched under SYSTEM account.

---

## 🛡️ Response Actions

- Isolated `vm-lab-mde` from the network  
- Performed full malware scan (no detections)  
- Maintained isolation due to abnormal SYSTEM activity  
- Submitted ticket to re-image the device  

<img width="825" height="247" alt="image" src="https://github.com/user-attachments/assets/a48fe1fd-6353-490e-baa5-727945002abd" />

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- No alerting on internal port scanning behavior  
- Lack of controls detecting unauthorized SYSTEM script execution  

### Recommendations
- Alert on sequential failed connection patterns  
- Monitor PowerShell execution under SYSTEM context  
- Enable behavioral detections for discovery activity  
- Implement tighter script control and execution logging  

---

## 🧾 Final Assessment

`vm-lab-mde` exhibited unauthorized discovery behavior consistent with internal port scanning. While no malware was detected, the SYSTEM-level execution context and unauthorized script creation elevated risk. The device was isolated and scheduled for re-imaging to ensure environmental integrity. This hunt demonstrates effective detection of internal reconnaissance and rapid containment.

---

## 📎 Analyst Notes

- Evidence reproducible via Microsoft Defender Advanced Hunting  
- MITRE ATT&CK aligned investigation  
- Demonstrates discovery detection, process correlation, and containment  

---
