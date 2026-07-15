# Active Directory Persistence & "Shadow Admin" Detection Lab

## Objective
This hands-on lab focuses on detecting privilege escalation and persistence techniques within an Active Directory environment using **Splunk Enterprise**. By simulating a "Shadow Admin" attack—where a threat actor secretly creates a backdoor user and immediately promotes them to an administrative group—this project demonstrates how to configure advanced OS auditing, execute threat simulation scripts, and construct real-time correlation queries to alert security operations teams.

### Skills Demonstrated:
*   **SIEM Engineering:** Writing advanced Splunk Search Processing Language (SPL) to correlate multi-event attack chains.
*   **Threat Simulation:** Simulating local privilege escalation and persistence actions in Windows Server.
*   **OS Auditing Configuration:** Enabling granular Local Security Policies via `auditpol`.
*   **Security Visualization:** Building high-severity dashboard alerts using Splunk Dashboard Studio.

---

## Environment & Tools
*   **Operating System:** Windows Server 2019 (Domain Controller VM)
*   **SIEM Platform:** Splunk Enterprise (local instance)
*   **Data Source:** Windows Security Event Logs (`WinEventLog:Security`)
*   **Telemetry Agent:** Splunk Universal Forwarder

---

## Lab Walkthrough

### Phase 1: Enabling Account Management Auditing
To ensure the Windows kernel records the security events generated during account creation and group modifications, granular auditing was enforced via PowerShell.

```powershell
# Enforce auditing for user creations and group membership changes
auditpol /set /category:"Account Management" /success:enable



Phase 2: Threat Simulation ("Shadow Admin" Creation)
Acting as the threat actor, a PowerShell script was executed to create a decoy local IT support account (SupportTech) and immediately escalate its privileges by adding it to the local Administrators group.

PowerShell
# 1. Create a backdoor local user account
$Password = ConvertTo-SecureString "BackdoorPass123!" -AsPlainText -Force
New-LocalUser -Name "SupportTech" -Password $Password -Description "Decoy IT Support Account"

# 2. Immediately escalate the account to the Local Administrators group
Add-LocalGroupMember -Group "Administrators" -Member "SupportTech"


Phase 3: Telemetry Analysis & Correlation
To detect this attack, we look for a specific chain of events occurring within a tight time window:

Event ID 4720: A user account was created.

Event ID 4732: A member was added to a security-enabled local group.

Instead of alerts firing for every routine user creation, we built an advanced Correlation Query in Splunk to flag only when the same account is created and escalated:

Code snippet
index="wineventlog" sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| stats values(EventCode) as EventCodes, latest(_time) as Time by TargetUserName
| eval Status=if(mvcount(EventCodes)>1, "⚠️ CRITICAL: Shadow Admin Backdoor Detected", "Normal Account Activity")
| search EventCodes=4720 EventCodes=4732
| fieldformat Time=strftime(Time, "%Y-%m-%d %H:%M:%S")
| rename TargetUserName as "Suspicious Account", EventCodes as "Captured Event IDs"
| table Time, "Suspicious Account", "Captured Event IDs", Status




Phase 4: SOC Dashboard & Visualization
To make this alert actionable for SOC Analysts, a dedicated high-priority table panel was added to the Windows Domain Controller Security Overview dashboard.

Using Splunk Dashboard Studio, dynamic column formatting was configured to highlight any active "CRITICAL" detections in a solid red background.

📍 Dashboard Configuration (Source Code Snippet)
JSON
"viz_shadow_admin_alerts": {
  "type": "splunk.table",
  "options": {
    "dataValuesFormatting": [
      {
        "field": "Status",
        "format": "background",
        "rules": [
          {
            "match": "⚠️ CRITICAL: Shadow Admin Backdoor Detected",
            "value": "#FF0000"
          }
        ]
      }
    ]
  }
}
