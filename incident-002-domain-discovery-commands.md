# Incident Summary: Spike in Domain Discovery Commands

## Incident ID
INC-002

## Incident Type
Suspicious Activity / Potential Lateral Movement

## Detection Source
SIEM – Endpoint & Active Directory Monitoring

## Alert Overview
A SIEM alert was triggered due to a spike in domain discovery-related commands executed on a Windows server. These commands are commonly associated with reconnaissance activity during post-compromise phases, particularly by attackers attempting to enumerate users, groups, and privileges within an Active Directory environment.

## Affected Host
- **Hostname:** DMZ-MSEXCHANGE-2013
- **Operating System:** Windows Server 2012 R2
- **User Context:** NT AUTHORITY\SYSTEM

## Timeline
- **Alert Generated:** March 27, 2025 at 19:56
- **Severity:** Medium
- **Status:** In Progress
- **Verdict:** True Positive

## Observed Commands
The following commands were detected in a short time window:
- `whoami`
- `net user`
- `net group "Domain Admins"`
- `dir`
- `hostname`

## Process Information
- **Source Process:** `C:\Windows\System32\cmd.exe`
- **Parent Process:** `C:\Users\Public\revshell.exe`
- **Grandparent Process:** `C:\Windows\System32\inetsrv\w3wp.exe`

## Indicators of Compromise (IOCs)
- Use of domain enumeration commands
- Execution under SYSTEM context
- Presence of a reverse shell binary (`revshell.exe`)
- Unusual parent-child process relationship
- Commands executed in rapid succession

## Investigation Steps
- Reviewed SIEM alert metadata and command execution timeline
- Validated legitimacy of executed commands
- Analyzed process tree for abnormal behavior
- Checked for known administrative or maintenance activity
- Correlated findings with known attacker reconnaissance techniques

## Findings
- Commands are consistent with Active Directory reconnaissance
- Parent process (`revshell.exe`) is not a legitimate system binary
- Activity does not align with normal administrative behavior
- Indicates possible post-exploitation discovery phase

## MITRE ATT&CK Mapping
- **T1087 – Account Discovery**
- **T1069 – Permission Group Discovery**
- **TA0007 – Discovery**
- **TA0008 – Lateral Movement (Potential)**

## Severity Assessment
**Medium**  
The activity indicates suspicious reconnaissance behavior with potential to escalate into lateral movement if left unchecked. No confirmed data exfiltration or privilege escalation was observed at this stage.

## Response Actions
- Classified alert as a True Positive
- Recommended immediate host isolation
- Advised termination of suspicious processes
- Suggested full endpoint forensic analysis
- Recommended credential review and password resets for privileged accounts

## Outcome
The alert was identified as malicious reconnaissance activity. Containment and remediation actions were recommended to prevent further progression of a potential intrusion.

## Lessons Learned
- Domain discovery commands are strong indicators of attacker reconnaissance
- Process tree analysis is critical for identifying malicious execution chains
- Early detection helps prevent lateral movement and escalation
