markdown
# Threat Detection with Microsoft Sentinel

## 📌 Project Overview
This project demonstrates a fully functional cloud-native SIEM (Security Information and Event Management) pipeline using **Microsoft Sentinel**. It simulates a brute-force attack against a Windows Virtual Machine, ingests the security logs, and automatically triggers a High-Severity incident using KQL (Kusto Query Language) mapped to the MITRE ATT&CK framework.

## 🏗️ Architecture Diagram

```mermaid
flowchart TD
    A[Attacker via RDP] -->|Failed Logins / Event ID 4625| B(Windows Server VM)
    B -->|Azure Monitor Agent| C[Data Collection Rule]
    C -->|Ingest Logs| D[Log Analytics Workspace]
    D -->|KQL Detection Rule| E[Microsoft Sentinel]
    E -->|Generates| F[High Severity Incident]
🛠️ Technologies Used
Microsoft Sentinel (SIEM)

Azure Monitor Agent (AMA) (Log collection)

Data Collection Rules (DCR) (Log routing)

KQL (Threat hunting & detection logic)

ARM Templates / JSON (Infrastructure as Code for rules)

🚀 How It Works
The Attack: A simulated attacker attempts multiple RDP logins to the Windows VM with the wrong password.

The Logs: Windows generates Security Event ID 4625 (An account failed to log on).

The Pipeline: The Azure Monitor Agent captures these events and routes them to the Log Analytics workspace via a DCR.

The Detection: A Scheduled Analytics Rule runs every 5 minutes. It aggregates failed logins by IP and Account.

The Alert: If 5 or more failed logins occur within a 5-minute window, Sentinel generates a High-Severity Incident mapped to MITRE ATT&CK T1110 (Brute Force).

💻 The KQL Detection Query
kql
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Account = tostring(TargetUserName), Computer, IpAddress, bin(TimeGenerated, 5m)
| where FailedLogons >= 5
📸 Proof of Concept
Failed Logins Detected (KQL Query):
https://screenshots/logs-success.png

Incident Generated:
https://screenshots/incident-detected.png

⚠️ Engineering Notes & Workarounds
During this lab, the standard Portal UI for Sentinel was restricted due to Microsoft Entra ID permission limitations (Student Account). To bypass this and follow Infrastructure as Code (IaC) principles, the Data Collection Rules and Analytics Rules were deployed using custom JSON templates via the Azure Portal. Furthermore, because the initial VM was a Windows 10 Client, the Azure Monitor Agent was deployed via PowerShell in Azure Cloud Shell to bypass standard extension gallery restrictions.
