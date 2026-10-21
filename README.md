Threat Detection with Microsoft Sentinel

## 📌 Project Overview
This project demonstrates a fully functional cloud-native SIEM (Security Information and Event Management) pipeline using **Microsoft Sentinel**. It simulates an RDP brute-force attack against a Windows Virtual Machine, ingests the security logs, and automatically triggers a High-Severity incident using KQL (Kusto Query Language) mapped to the MITRE ATT&CK framework.

## 🏗️ Architecture
![Sentinel Architecture](Azure%20Sentinel%20RDP%20Attack%20Detection%20Flow.png)

## 🛠️ Technologies Used
* **Microsoft Sentinel** (SIEM)
* **Azure Monitor Agent (AMA)** (Log collection)
* **Data Collection Rules (DCR)** (Log routing)
* **KQL** (Threat hunting & detection logic)

## 🚀 How It Works
1. **The Attack:** A simulated attacker attempts multiple RDP logins to the Windows VM with the wrong password.
2. **The Logs:** Windows generates Security Event ID `4625` (An account failed to log on).
3. **The Pipeline:** The Azure Monitor Agent captures these events and routes them to the Log Analytics workspace via a DCR.
4. **The Detection:** A Scheduled Analytics Rule runs every 5 minutes. It aggregates failed logins by IP and Account.
5. **The Alert:** If 5 or more failed logins occur within a 5-minute window, Sentinel generates a High-Severity Incident mapped to MITRE ATT&CK **T1110 (Brute Force)**.

## 💻 The KQL Detection Query
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Account = tostring(TargetUserName), Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedLogons >= 5
📸 Proof of Concept
Failed Logins Detected (KQL Query):
https://github.com/vaino118/Threat-Detection-with-Microsoft-Sentinel/blob/main/incident-detected.png

Detection Rule Triggered (Incident):
https://incident-detected.png/

⚠️ Engineering Notes & Workarounds
Because this was built on an Azure Student Account, Microsoft Entra ID permissions restricted the standard Defender portal UI. To bypass this and follow Infrastructure as Code (IaC) principles, the Data Collection Rules and Analytics Rules were deployed using custom JSON ARM templates via the Azure Portal. Furthermore, because the initial VM was a Windows 10 Client, the Azure Monitor Agent was deployed via PowerShell in Azure Cloud Shell to bypass standard extension gallery restrictions.
