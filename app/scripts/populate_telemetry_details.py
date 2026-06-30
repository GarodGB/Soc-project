"""
Populate Telemetry Source Details
==================================
Adds comprehensive Event ID data, prerequisites, key fields, and
MITRE ATT&CK mappings to every telemetry source card.

Usage:
    python app/scripts/populate_telemetry_details.py
"""

import sqlite3
import json
import os
import sys

DETAILS = {

# ═══════════════════════════════════════════════════════════════════════════════
#  WINDOWS SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

"Sysmon": {
    "description": "System Monitor (Sysmon) is a Windows system service that logs detailed system activity to the Windows event log. It provides granular visibility into process creation, network connections, file changes, registry modifications, and more. Sysmon is considered the single most valuable endpoint telemetry source for detection engineering because it captures data that native Windows logging misses entirely.",
    "detection_value": "critical",
    "log_path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
    "log_channel": "Microsoft-Windows-Sysmon/Operational",
    "prerequisites": [
        "Sysmon must be downloaded and installed from Microsoft Sysinternals (not included in Windows by default)",
        "A Sysmon XML configuration file must be deployed — without it, Sysmon logs almost nothing useful",
        "Recommended config: SwiftOnSecurity sysmon-config or Olaf Hartong sysmon-modular",
        "Sysmon service must be running (sysmon64 -i config.xml to install)",
        "Wazuh agent must be configured to read the Sysmon event channel in ossec.conf",
        "Group Policy or MDM can deploy Sysmon at scale in enterprise environments"
    ],
    "key_fields": [
        "ProcessId", "Image", "CommandLine", "ParentImage", "ParentCommandLine",
        "User", "Hashes", "TargetFilename", "DestinationIp", "DestinationPort",
        "SourceIp", "SourcePort", "Protocol", "TargetObject", "Details",
        "SourceProcessGuid", "TargetProcessGuid", "CallTrace", "QueryName"
    ],
    "critical_event_ids": [
        {
            "id": "1",
            "name": "Process Creation",
            "description": "Logs every process that starts on the system with full command line, parent process, user, working directory, and file hashes. This is the #1 most important Event ID for detection — it reveals malicious commands, LOLBin abuse, encoded PowerShell, lateral movement tools, and virtually every hands-on-keyboard attack.",
            "mitre": ["T1059", "T1204", "T1053", "T1569"]
        },
        {
            "id": "2",
            "name": "File Creation Time Changed",
            "description": "Detects timestomping — when an attacker modifies a file's creation time to blend in with legitimate system files. A strong indicator of anti-forensics activity.",
            "mitre": ["T1070.006"]
        },
        {
            "id": "3",
            "name": "Network Connection",
            "description": "Logs outbound/inbound TCP/UDP connections with the source process, destination IP, port, and protocol. Essential for detecting C2 beacons, data exfiltration, lateral movement, and reverse shells.",
            "mitre": ["T1071", "T1095", "T1572", "T1571"]
        },
        {
            "id": "5",
            "name": "Process Terminated",
            "description": "Logs when a process ends. Useful for correlating with Event ID 1 to calculate process runtime and detect short-lived malicious processes.",
            "mitre": ["T1059"]
        },
        {
            "id": "6",
            "name": "Driver Loaded",
            "description": "Logs kernel drivers being loaded with signature status and hash. Detects rootkits, vulnerable driver exploitation (BYOVD), and unsigned kernel modules.",
            "mitre": ["T1014", "T1068"]
        },
        {
            "id": "7",
            "name": "Image Loaded (DLL)",
            "description": "Logs every DLL loaded by a process with hash and signature info. Detects DLL sideloading, DLL injection, and unsigned DLL loading by trusted processes.",
            "mitre": ["T1574.001", "T1574.002", "T1055.001"]
        },
        {
            "id": "8",
            "name": "CreateRemoteThread",
            "description": "Logs when a process creates a thread in another process — a classic injection technique. Detects process injection, shellcode injection, and credential dumping tools that inject into LSASS.",
            "mitre": ["T1055", "T1055.003"]
        },
        {
            "id": "10",
            "name": "ProcessAccess",
            "description": "Logs when a process opens a handle to another process. Critical for detecting LSASS credential dumping (Mimikatz), process injection preparation, and debugging API abuse. Monitor for access to lsass.exe specifically.",
            "mitre": ["T1003.001", "T1055"]
        },
        {
            "id": "11",
            "name": "FileCreate",
            "description": "Logs file creation events with full path. Detects malware dropping payloads, script file creation in suspicious locations (Temp, AppData), and webshell deployment.",
            "mitre": ["T1105", "T1204.002"]
        },
        {
            "id": "12",
            "name": "Registry Object Added/Deleted",
            "description": "Logs registry key and value creation or deletion. Detects persistence mechanisms (Run keys, Services), defense evasion, and configuration changes.",
            "mitre": ["T1547.001", "T1112"]
        },
        {
            "id": "13",
            "name": "Registry Value Set",
            "description": "Logs registry value modifications. Essential for detecting persistence via Run/RunOnce keys, service creation, COM object hijacking, and security tool tampering.",
            "mitre": ["T1547.001", "T1112", "T1546.015"]
        },
        {
            "id": "14",
            "name": "Registry Object Renamed",
            "description": "Logs registry key renames, which can indicate evasion attempts to hide persistence mechanisms by renaming registry keys.",
            "mitre": ["T1112"]
        },
        {
            "id": "15",
            "name": "FileCreateStreamHash",
            "description": "Logs Alternate Data Stream (ADS) creation with hash. Attackers hide payloads in ADS to evade file system inspection. Also captures files downloaded from the internet (Zone.Identifier stream).",
            "mitre": ["T1564.004"]
        },
        {
            "id": "17",
            "name": "Pipe Created",
            "description": "Logs named pipe creation. Detects C2 frameworks that use named pipes for communication (Cobalt Strike, Metasploit), inter-process communication abuse, and lateral movement tools.",
            "mitre": ["T1559"]
        },
        {
            "id": "18",
            "name": "Pipe Connected",
            "description": "Logs connections to named pipes. Complements Event ID 17 to identify which process is communicating via the pipe, revealing C2 channels and lateral movement.",
            "mitre": ["T1559"]
        },
        {
            "id": "22",
            "name": "DNS Query",
            "description": "Logs DNS queries made by each process. Detects DNS-based C2, domain generation algorithms (DGA), DNS tunneling, and suspicious domain lookups by unexpected processes.",
            "mitre": ["T1071.004", "T1568.002", "T1572"]
        },
        {
            "id": "23",
            "name": "FileDelete (Archived)",
            "description": "Logs file deletions and optionally archives the deleted file content. Detects evidence destruction, log tampering, and ransomware file deletion patterns.",
            "mitre": ["T1070.004", "T1485"]
        },
        {
            "id": "25",
            "name": "Process Tampering",
            "description": "Detects process image tampering techniques like process hollowing and herpaderping where the on-disk image differs from the in-memory image. High-fidelity detection for advanced evasion.",
            "mitre": ["T1055.012"]
        },
        {
            "id": "26",
            "name": "FileDeleteDetected",
            "description": "Logs file deletion events without archiving the file content. Lighter weight than Event ID 23 but still captures deletion activity for forensic timeline reconstruction.",
            "mitre": ["T1070.004"]
        }
    ]
},

"Windows Security Event Log": {
    "description": "The Windows Security Event Log records authentication events, privilege use, policy changes, and object access. It is the primary audit trail for security investigations on Windows systems. Without proper audit policies configured, most critical events are NOT logged by default — making audit policy configuration essential.",
    "detection_value": "critical",
    "log_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    "log_channel": "Security",
    "prerequisites": [
        "Advanced Audit Policy Configuration must be enabled via Group Policy (Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy)",
        "Key policies to enable: Audit Logon Events (Success/Failure), Audit Process Creation (Success), Audit Object Access, Audit Account Management, Audit Policy Change",
        "Command Line auditing requires: 'Include command line in process creation events' policy enabled",
        "PowerShell logging requires separate configuration in PowerShell policies",
        "Security log size must be increased from default 20MB (recommend 1GB+ for production)",
        "Wazuh agent ossec.conf must include the Security channel in the eventchannel configuration"
    ],
    "key_fields": [
        "EventID", "TimeCreated", "TargetUserName", "TargetDomainName", "IpAddress",
        "LogonType", "WorkstationName", "ProcessName", "SubjectUserName", "Status",
        "SubStatus", "FailureReason", "PrivilegeList", "ServiceName", "TokenElevationType",
        "NewProcessName", "CommandLine", "ParentProcessName", "TicketOptions"
    ],
    "critical_event_ids": [
        {
            "id": "4624",
            "name": "Successful Logon",
            "description": "Records every successful authentication. The LogonType field is critical: Type 2=Interactive (local), Type 3=Network (SMB/WinRM), Type 7=Unlock, Type 10=RemoteInteractive (RDP). Network logons from unexpected sources indicate lateral movement.",
            "mitre": ["T1078", "T1021"]
        },
        {
            "id": "4625",
            "name": "Failed Logon",
            "description": "Records failed authentication attempts with reason codes. Multiple failures in short time = brute force. Status 0xC000006D = bad username, 0xC000006A = bad password, 0xC0000234 = account locked. Critical for detecting password spraying and credential stuffing.",
            "mitre": ["T1110", "T1110.001", "T1110.003"]
        },
        {
            "id": "4648",
            "name": "Logon with Explicit Credentials",
            "description": "Logged when a user supplies different credentials than their current session (runas, mapping drives with different creds). Detects credential abuse and lateral movement preparation.",
            "mitre": ["T1078", "T1550"]
        },
        {
            "id": "4672",
            "name": "Special Privileges Assigned",
            "description": "Logged when a user logs on with administrative or other sensitive privileges (SeDebugPrivilege, SeTcbPrivilege, etc). Tracks which accounts have elevated access — unusual privilege assignments are red flags.",
            "mitre": ["T1078", "T1134"]
        },
        {
            "id": "4688",
            "name": "Process Creation",
            "description": "Native Windows process creation logging. Less detailed than Sysmon Event 1 but available without installing anything extra. Requires 'Audit Process Creation' policy AND 'Include command line in process creation events' to capture the command line.",
            "mitre": ["T1059", "T1204"]
        },
        {
            "id": "4697",
            "name": "Service Installed",
            "description": "Logged when a new Windows service is installed. Attackers create malicious services for persistence and privilege escalation. Also detected by System Event 7045.",
            "mitre": ["T1543.003", "T1569.002"]
        },
        {
            "id": "4698",
            "name": "Scheduled Task Created",
            "description": "Records creation of a new scheduled task with full task XML. One of the most common persistence mechanisms — attackers schedule tasks to run malware on boot or at intervals.",
            "mitre": ["T1053.005"]
        },
        {
            "id": "4720",
            "name": "User Account Created",
            "description": "Logs creation of new local or domain user accounts. Unexpected account creation is a strong indicator of compromise — attackers create backdoor accounts for persistent access.",
            "mitre": ["T1136.001", "T1136.002"]
        },
        {
            "id": "4724",
            "name": "Password Reset Attempt",
            "description": "Logged when someone attempts to reset another user's password. Unauthorized password resets indicate account takeover attempts.",
            "mitre": ["T1098"]
        },
        {
            "id": "4728",
            "name": "Member Added to Security-Enabled Global Group",
            "description": "Records when a user is added to a domain group. Adding accounts to Domain Admins or other privileged groups is a critical indicator of privilege escalation.",
            "mitre": ["T1098", "T1078.002"]
        },
        {
            "id": "4732",
            "name": "Member Added to Local Group",
            "description": "Records when a user is added to a local security group such as Administrators. Detects local privilege escalation via group membership manipulation.",
            "mitre": ["T1098", "T1078"]
        },
        {
            "id": "4740",
            "name": "Account Locked Out",
            "description": "Logged when an account is locked due to too many failed attempts. A spike in lockouts indicates an active brute force or password spray attack.",
            "mitre": ["T1110"]
        },
        {
            "id": "4768",
            "name": "Kerberos TGT Requested",
            "description": "Logs Kerberos Ticket Granting Ticket (TGT) requests. Unusual TGT requests (encryption downgrade to RC4, non-standard tools) indicate Kerberoasting or Golden Ticket attacks.",
            "mitre": ["T1558.001", "T1558.003"]
        },
        {
            "id": "4769",
            "name": "Kerberos Service Ticket Requested",
            "description": "Logs Kerberos Service Ticket (TGS) requests. High volume of TGS requests for service accounts with RC4 encryption indicates Kerberoasting — harvesting service account password hashes.",
            "mitre": ["T1558.003"]
        },
        {
            "id": "4771",
            "name": "Kerberos Pre-Authentication Failed",
            "description": "Logs failed Kerberos authentication. Used to detect AS-REP Roasting attacks where pre-authentication is disabled on accounts, allowing offline password cracking.",
            "mitre": ["T1558.004"]
        },
        {
            "id": "4776",
            "name": "NTLM Authentication",
            "description": "Logs NTLM (legacy) credential validation attempts. NTLM in environments that should use Kerberos indicates Pass-the-Hash attacks, NTLM relay, or legacy system abuse.",
            "mitre": ["T1550.002"]
        },
        {
            "id": "5140",
            "name": "Network Share Accessed",
            "description": "Logs when a network share (like C$, ADMIN$, IPC$) is accessed. Admin share access from unexpected hosts is a strong indicator of lateral movement.",
            "mitre": ["T1021.002", "T1135"]
        },
        {
            "id": "4657",
            "name": "Registry Value Modified",
            "description": "Logs registry changes when auditing is enabled on specific keys via SACL. Detects persistence, security tool tampering, and configuration changes to critical registry paths.",
            "mitre": ["T1112", "T1547.001"]
        },
        {
            "id": "1102",
            "name": "Audit Log Cleared",
            "description": "Logged when the Security event log is cleared. Almost always indicates an attacker covering their tracks — this should trigger an immediate high-priority alert.",
            "mitre": ["T1070.001"]
        }
    ]
},

"Windows System Event Log": {
    "description": "The Windows System Event Log captures kernel, driver, service, and system component events. While less granular than Security logs for authentication, it is critical for detecting service manipulation, driver loading, system shutdowns, and event log tampering.",
    "detection_value": "high",
    "log_path": "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
    "log_channel": "System",
    "prerequisites": [
        "Enabled by default on all Windows systems — no additional configuration needed",
        "Increase log file size from default 20MB to at least 256MB for better retention",
        "Wazuh agent ossec.conf must include the System channel",
        "Some events require specific services to be running (e.g., Service Control Manager)"
    ],
    "key_fields": [
        "EventID", "TimeCreated", "Provider", "Level", "ServiceName",
        "ImagePath", "ServiceType", "StartType", "AccountName",
        "BugCheckCode", "DriverName"
    ],
    "critical_event_ids": [
        {
            "id": "7034",
            "name": "Service Crashed",
            "description": "Service terminated unexpectedly. Repeated crashes of security services (Windows Defender, Wazuh agent) may indicate an attacker killing protective services.",
            "mitre": ["T1489"]
        },
        {
            "id": "7035",
            "name": "Service Control Manager",
            "description": "A service was sent a start or stop command. Tracks when services are being controlled — unexpected stop commands to security services are suspicious.",
            "mitre": ["T1569.002"]
        },
        {
            "id": "7036",
            "name": "Service Started/Stopped",
            "description": "Records the actual state change of services. Correlate with 7035 to see who started/stopped which service. Monitor for security service disruption.",
            "mitre": ["T1569.002", "T1489"]
        },
        {
            "id": "7040",
            "name": "Service Start Type Changed",
            "description": "Logged when a service's startup type is changed (e.g., from Automatic to Disabled). Attackers disable security services or enable malicious ones for persistence.",
            "mitre": ["T1562.001"]
        },
        {
            "id": "7045",
            "name": "New Service Installed",
            "description": "A new service was installed on the system. This is a high-fidelity persistence indicator — legitimate service installations are rare on production systems. Check ImagePath for suspicious binaries or command-line payloads.",
            "mitre": ["T1543.003", "T1569.002"]
        },
        {
            "id": "1074",
            "name": "System Shutdown/Restart",
            "description": "Records who initiated a system shutdown or restart and the reason. Unexpected reboots may indicate patching of a rootkit or kernel exploit.",
            "mitre": ["T1529"]
        },
        {
            "id": "6005",
            "name": "Event Log Service Started",
            "description": "Marks when the Event Log service starts (usually after boot). A gap between shutdown and this event indicates the system was offline.",
            "mitre": []
        },
        {
            "id": "6006",
            "name": "Event Log Service Stopped",
            "description": "Marks when the Event Log service stops cleanly. If this event is missing before a 6005, the system was not shut down cleanly (crash or power loss).",
            "mitre": []
        },
        {
            "id": "104",
            "name": "Event Log Cleared",
            "description": "An event log was cleared. Similar to Security 1102 — almost always indicates anti-forensics. Should generate an immediate alert.",
            "mitre": ["T1070.001"]
        }
    ]
},

"Windows Application Event Log": {
    "description": "The Windows Application Event Log captures events from installed applications, runtime errors, application crashes, and installation activity. While less security-focused than Security or Sysmon logs, it provides critical visibility into application-layer attacks, exploit success indicators, and software installation tracking.",
    "detection_value": "medium",
    "log_path": "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    "log_channel": "Application",
    "prerequisites": [
        "Enabled by default on all Windows systems",
        "Applications must be configured to log to the Application event log",
        "Windows Error Reporting (WER) service should be enabled for crash data",
        "Increase log file size for better retention in production",
        "Wazuh agent ossec.conf must include the Application channel"
    ],
    "key_fields": [
        "EventID", "Source", "Level", "FaultingApplicationName",
        "FaultingModuleName", "ExceptionCode", "ProductName",
        "ProductVersion", "InstallerName"
    ],
    "critical_event_ids": [
        {
            "id": "1000",
            "name": "Application Error",
            "description": "Logs application crashes with the faulting module and exception code. Repeated crashes in security software may indicate tampering. Crashes in browsers or Office apps may indicate exploit attempts.",
            "mitre": ["T1203"]
        },
        {
            "id": "1001",
            "name": "Windows Error Reporting",
            "description": "Detailed crash report including faulting process, module, and call stack offsets. Can reveal exploitation attempts (heap spray crashes, buffer overflow signatures).",
            "mitre": ["T1203"]
        },
        {
            "id": "1002",
            "name": "Application Hang",
            "description": "Application stopped responding. Hangs in critical processes may indicate resource exhaustion attacks (DoS) or deadlocks caused by injection.",
            "mitre": ["T1499"]
        },
        {
            "id": "11707",
            "name": "Installation Completed Successfully",
            "description": "Windows Installer (MSI) package installed successfully. Track unexpected software installations — attackers use MSI packages for payload delivery and persistence.",
            "mitre": ["T1218.007"]
        },
        {
            "id": "11708",
            "name": "Installation Failed",
            "description": "Windows Installer package failed. Failed installation attempts from unusual sources may indicate blocked attack attempts.",
            "mitre": ["T1218.007"]
        },
        {
            "id": "1033",
            "name": "MSI Install Complete",
            "description": "Confirms successful MSI-based installation with product name and version. Cross-reference with known-good software inventory to detect unauthorized installations.",
            "mitre": ["T1105"]
        }
    ]
},

"PowerShell Operational Log": {
    "description": "The PowerShell Operational Log captures script execution, module loading, and command invocation when Script Block Logging and Module Logging are enabled. PowerShell is the #1 tool used in post-exploitation — nearly every modern attack framework uses it. Without these logs enabled, you are blind to the most common attack vector on Windows.",
    "detection_value": "critical",
    "log_path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
    "log_channel": "Microsoft-Windows-PowerShell/Operational",
    "prerequisites": [
        "Script Block Logging MUST be enabled: Group Policy → Administrative Templates → Windows Components → PowerShell → Turn on PowerShell Script Block Logging",
        "Module Logging should be enabled: same GPO path → Turn on Module Logging (set modules to '*' for all)",
        "PowerShell Transcription (optional but recommended): logs full session I/O to text files",
        "Constrained Language Mode recommended for non-admin users to limit PowerShell attack surface",
        "Log file size should be increased to 512MB+ — PowerShell logging can be very verbose",
        "Wazuh agent ossec.conf must include the PowerShell Operational channel"
    ],
    "key_fields": [
        "EventID", "ScriptBlockText", "ScriptBlockId", "Path", "MessageNumber",
        "MessageTotal", "Level", "HostApplication", "CommandName",
        "CommandType", "EngineVersion", "RunspaceId"
    ],
    "critical_event_ids": [
        {
            "id": "4104",
            "name": "Script Block Logging",
            "description": "THE MOST IMPORTANT PowerShell Event ID. Logs the full text of every PowerShell script block executed, including dynamically generated and obfuscated code AFTER deobfuscation. This reveals: encoded commands (Base64), Invoke-Mimikatz, Invoke-WebRequest downloads, AMSI bypass attempts, and any PowerShell-based attack tool. Without this Event ID enabled, you cannot see what PowerShell is actually doing.",
            "mitre": ["T1059.001", "T1027", "T1140"]
        },
        {
            "id": "4103",
            "name": "Module Logging",
            "description": "Logs PowerShell pipeline execution details — which cmdlets are called with what parameters. Shows the actual commands and their arguments. Complements 4104 by showing execution flow and parameter values.",
            "mitre": ["T1059.001"]
        },
        {
            "id": "4105",
            "name": "Script Block Start",
            "description": "Marks the beginning of a script block execution. Useful for correlating multi-part script blocks (when a script is split across multiple 4104 events via MessageNumber/MessageTotal).",
            "mitre": ["T1059.001"]
        },
        {
            "id": "4106",
            "name": "Script Block Stop",
            "description": "Marks the end of a script block execution. Together with 4105, provides the execution duration for forensic timeline analysis.",
            "mitre": ["T1059.001"]
        },
        {
            "id": "40961",
            "name": "PowerShell Console Starting",
            "description": "Logs every time a PowerShell console is opened with the host application. Detects PowerShell being launched by unusual parent processes (cmd.exe from Office macros, WMI, scheduled tasks).",
            "mitre": ["T1059.001"]
        },
        {
            "id": "53504",
            "name": "PowerShell Named Pipe Connected",
            "description": "Logs PowerShell remoting connections via named pipes. Detects lateral movement using PowerShell Remoting (Enter-PSSession, Invoke-Command to remote hosts).",
            "mitre": ["T1059.001", "T1021.006"]
        }
    ]
},

"Windows Defender Log": {
    "description": "Windows Defender Operational Log records all antivirus and endpoint protection activity including malware detections, real-time protection state changes, scan results, definition updates, and exclusion modifications. Monitoring this log is essential because attackers frequently disable or tamper with Defender as their first action after gaining access.",
    "detection_value": "high",
    "log_path": "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
    "log_channel": "Microsoft-Windows-Windows Defender/Operational",
    "prerequisites": [
        "Windows Defender must be the active antivirus (not replaced by a third-party AV)",
        "Real-time protection should be enabled and enforced via Group Policy",
        "Cloud-delivered protection and automatic sample submission should be enabled",
        "Tamper Protection should be enabled to prevent attackers from disabling Defender",
        "Wazuh agent ossec.conf must include the Windows Defender Operational channel",
        "Exclusions should be audited — attackers add exclusions to hide malware"
    ],
    "key_fields": [
        "EventID", "Threat Name", "Threat ID", "Severity", "Path",
        "Detection Source", "Process Name", "Action", "Error Code",
        "Category", "Detection User", "Remediation Action"
    ],
    "critical_event_ids": [
        {
            "id": "1006",
            "name": "Malware Detected",
            "description": "The antimalware engine found malware. Includes threat name, severity, affected file/path, and the process that triggered detection. Immediate triage required — verify if the malware was blocked or if further action is needed.",
            "mitre": ["T1204.002"]
        },
        {
            "id": "1007",
            "name": "Action Taken on Malware",
            "description": "Action was performed on detected malware (quarantine, remove, allow). Verify the action was successful. 'Allow' actions may indicate an attacker added an exclusion.",
            "mitre": ["T1204.002"]
        },
        {
            "id": "1008",
            "name": "Malware Action Failed",
            "description": "The antimalware engine tried to take action but failed. The malware is still active. This requires immediate manual investigation and remediation.",
            "mitre": ["T1562.001"]
        },
        {
            "id": "1116",
            "name": "MAPS/Cloud Detection",
            "description": "Microsoft cloud protection (MAPS) detected a threat. Cloud-based detections often catch zero-day or polymorphic malware that signature-based detection misses.",
            "mitre": ["T1204.002"]
        },
        {
            "id": "1117",
            "name": "MAPS Action Taken",
            "description": "Cloud-delivered protection took action on a threat. Verify the action was successful and correlate with the 1116 detection event.",
            "mitre": ["T1204.002"]
        },
        {
            "id": "5001",
            "name": "Real-Time Protection Disabled",
            "description": "Real-time protection was turned off. This is a CRITICAL alert — attackers disable real-time protection before deploying malware. If not initiated by IT staff, investigate immediately.",
            "mitre": ["T1562.001"]
        },
        {
            "id": "5004",
            "name": "Configuration Changed",
            "description": "Windows Defender configuration was modified. Watch for exclusion additions, feature disabling, and scan scope reduction — all common attacker techniques.",
            "mitre": ["T1562.001"]
        },
        {
            "id": "5007",
            "name": "Platform Configuration Changed",
            "description": "Antimalware platform configuration change. Detects tampering with Defender settings including adding path/process/extension exclusions that attackers use to whitelist their malware.",
            "mitre": ["T1562.001"]
        },
        {
            "id": "2001",
            "name": "Definition Update Failed",
            "description": "Signature/definition update failed. Persistent update failures may indicate network isolation by an attacker or deliberate prevention of AV updates.",
            "mitre": ["T1562.001"]
        },
        {
            "id": "5010",
            "name": "Scanning Disabled",
            "description": "Antimalware scanning was disabled. Combined with 5001 (real-time off) and 5007 (config changed), this pattern strongly indicates active defense evasion.",
            "mitre": ["T1562.001"]
        }
    ]
},

# ═══════════════════════════════════════════════════════════════════════════════
#  LINUX SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

"Linux auth.log": {
    "description": "The auth.log file records all authentication-related events on Linux systems including SSH logins, sudo commands, su switches, PAM authentication, and account lockouts. It is the primary source for detecting unauthorized access attempts, brute force attacks, and privilege escalation on Linux hosts.",
    "detection_value": "critical",
    "log_path": "/var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS)",
    "log_channel": "syslog facility auth/authpriv",
    "prerequisites": [
        "rsyslog or syslog-ng must be running and configured to write auth facility messages",
        "PAM (Pluggable Authentication Modules) must be configured — it is by default on all major distros",
        "SSH daemon (sshd) must have LogLevel set to INFO or VERBOSE in /etc/ssh/sshd_config",
        "journald ForwardToSyslog=yes must be set in /etc/systemd/journald.conf if using systemd",
        "Wazuh agent must monitor this file in ossec.conf (<localfile> configuration)",
        "File permissions should be 640 or stricter (owned by root:adm)"
    ],
    "key_fields": [
        "timestamp", "hostname", "process", "pid", "message",
        "username", "source_ip", "port", "auth_method",
        "session_status", "uid", "tty"
    ],
    "critical_event_ids": [
        {
            "id": "sshd:session_opened",
            "name": "SSH Login Success",
            "description": "Accepted password/publickey for user from IP. Every successful SSH login is logged with username, source IP, port, and auth method. Logins from unexpected IPs or at unusual times are high-priority alerts.",
            "mitre": ["T1021.004", "T1078"]
        },
        {
            "id": "sshd:failed_password",
            "name": "SSH Login Failed",
            "description": "Failed password for user from IP. Multiple failures from the same IP = brute force. Multiple failures across different usernames from one IP = password spray. Track with fail2ban or Wazuh active response.",
            "mitre": ["T1110", "T1110.001"]
        },
        {
            "id": "sshd:invalid_user",
            "name": "SSH Invalid User",
            "description": "Login attempt for a username that does not exist on the system. Indicates reconnaissance or credential stuffing with leaked credential lists.",
            "mitre": ["T1110", "T1078"]
        },
        {
            "id": "sudo:command",
            "name": "Sudo Command Executed",
            "description": "Records every sudo command with the executing user, target user (usually root), the working directory, and the full command. Unusual sudo usage by service accounts or commands like passwd, useradd, visudo are high-priority.",
            "mitre": ["T1548.003"]
        },
        {
            "id": "sudo:auth_failure",
            "name": "Sudo Authentication Failed",
            "description": "User attempted sudo but entered the wrong password or is not in the sudoers file. Repeated failures indicate privilege escalation attempts.",
            "mitre": ["T1548.003"]
        },
        {
            "id": "su:session",
            "name": "User Switch (su)",
            "description": "Records when a user switches to another account using 'su'. Watch for switches to root from unexpected users or service accounts.",
            "mitre": ["T1548"]
        },
        {
            "id": "pam:account_locked",
            "name": "PAM Account Locked",
            "description": "Account was locked due to excessive authentication failures. Indicates active brute force against that specific account.",
            "mitre": ["T1110"]
        },
        {
            "id": "useradd",
            "name": "User Account Created",
            "description": "New user account created via useradd or adduser. Unauthorized account creation is a strong indicator of persistence — attackers create backdoor accounts.",
            "mitre": ["T1136.001"]
        },
        {
            "id": "usermod:group_change",
            "name": "User Group Modified",
            "description": "User added to a group (especially sudo, wheel, root, docker). Adding a compromised account to privileged groups enables escalation.",
            "mitre": ["T1098"]
        }
    ]
},

"Linux syslog": {
    "description": "The syslog file is the central catch-all log for Linux systems, capturing messages from the kernel, system services, daemons, cron, and network subsystems. It uses the facility/priority routing system to categorize messages. While individual messages are less security-specific than auth.log, syslog provides critical context for incident investigation and detects system-level attacks.",
    "detection_value": "high",
    "log_path": "/var/log/syslog (Debian/Ubuntu) or /var/log/messages (RHEL/CentOS)",
    "log_channel": "syslog (all facilities except auth)",
    "prerequisites": [
        "rsyslog or syslog-ng must be installed and running",
        "Configuration in /etc/rsyslog.conf must route desired facilities to the syslog file",
        "journald ForwardToSyslog=yes recommended for systemd-based systems",
        "Remote syslog forwarding should be configured for centralized collection",
        "Wazuh agent must monitor this file in ossec.conf",
        "Log rotation via logrotate must be configured to prevent disk exhaustion"
    ],
    "key_fields": [
        "timestamp", "hostname", "facility", "priority", "process",
        "pid", "message", "kernel_module", "interface", "service_unit"
    ],
    "critical_event_ids": [
        {
            "id": "kernel:module_loaded",
            "name": "Kernel Module Loaded",
            "description": "A kernel module was loaded via insmod/modprobe. Rootkits install themselves as kernel modules. Unexpected module loads on production servers are high-priority.",
            "mitre": ["T1014", "T1547.006"]
        },
        {
            "id": "kernel:segfault",
            "name": "Kernel Segmentation Fault",
            "description": "A process crashed with a segfault. May indicate buffer overflow exploitation attempts. Repeated segfaults in the same process suggest active exploitation.",
            "mitre": ["T1203"]
        },
        {
            "id": "cron:command",
            "name": "Cron Job Executed",
            "description": "A scheduled cron job ran. Attackers add malicious cron entries for persistence. Monitor for new cron jobs that execute from /tmp, download scripts, or connect to external IPs.",
            "mitre": ["T1053.003"]
        },
        {
            "id": "systemd:service_start",
            "name": "Service Started/Stopped",
            "description": "A systemd service was started, stopped, or failed. Watch for new unknown services, security service stops, and services starting from unusual paths.",
            "mitre": ["T1543.002", "T1489"]
        },
        {
            "id": "kernel:iptables",
            "name": "Firewall Rule Change",
            "description": "Firewall rules were modified via iptables/nftables. Attackers modify firewall rules to open ports for C2 communication or disable network-level protections.",
            "mitre": ["T1562.004"]
        },
        {
            "id": "dhclient:lease",
            "name": "DHCP Lease Activity",
            "description": "Network interface obtained or released a DHCP lease. Unexpected network changes may indicate network manipulation or rogue DHCP.",
            "mitre": ["T1557"]
        },
        {
            "id": "kernel:usb",
            "name": "USB Device Connected",
            "description": "A USB device was plugged in. In secure environments, unauthorized USB devices could be used for data exfiltration or delivering malware via USB.",
            "mitre": ["T1091", "T1052.001"]
        }
    ]
},

"Linux auditd": {
    "description": "The Linux Audit Daemon (auditd) provides kernel-level auditing of system calls, file access, command execution, and permission changes. It is the most granular logging source available on Linux — equivalent to Sysmon on Windows. However, auditd logs NOTHING useful without explicit audit rules configured, making rule deployment the critical prerequisite.",
    "detection_value": "critical",
    "log_path": "/var/log/audit/audit.log",
    "log_channel": "Linux Audit Framework (auditd)",
    "prerequisites": [
        "auditd package must be installed (apt install auditd or yum install audit)",
        "auditd service must be enabled and running (systemctl enable --now auditd)",
        "AUDIT RULES MUST BE CONFIGURED in /etc/audit/rules.d/ — without rules, auditd logs almost nothing",
        "Recommended: deploy Florian Roth's Linux audit rules (auditd-attack) for MITRE ATT&CK coverage",
        "Key rules to add: EXECVE logging (-a always,exit -F arch=b64 -S execve), file watch rules for sensitive files, privilege escalation monitoring",
        "Buffer size may need increasing for high-throughput systems (-b 8192)",
        "Wazuh agent must monitor /var/log/audit/audit.log in ossec.conf"
    ],
    "key_fields": [
        "type", "msg", "arch", "syscall", "success", "exit",
        "pid", "ppid", "uid", "gid", "auid", "euid",
        "exe", "comm", "key", "cwd", "name", "nametype"
    ],
    "critical_event_ids": [
        {
            "id": "EXECVE",
            "name": "Command Execution",
            "description": "Records every command executed on the system with full arguments (when EXECVE audit rules are enabled). This is the Linux equivalent of Sysmon Event 1 — reveals reverse shells, reconnaissance commands, data exfiltration tools, and lateral movement scripts.",
            "mitre": ["T1059.004", "T1059"]
        },
        {
            "id": "SYSCALL",
            "name": "System Call",
            "description": "Records system calls matching audit rules (file open, connect, bind, execve, etc.). Provides the lowest-level visibility into what processes are doing at the kernel level.",
            "mitre": ["T1059", "T1106"]
        },
        {
            "id": "PATH",
            "name": "File Access Path",
            "description": "Records file paths accessed during audited operations. Detects access to sensitive files like /etc/shadow, /etc/passwd, SSH keys, and application credentials.",
            "mitre": ["T1003", "T1552.001"]
        },
        {
            "id": "USER_AUTH",
            "name": "User Authentication",
            "description": "Records authentication events at the audit framework level. Provides a second layer of auth logging independent of auth.log, useful for cross-correlation.",
            "mitre": ["T1078", "T1110"]
        },
        {
            "id": "USER_CMD",
            "name": "User Command (sudo)",
            "description": "Records commands executed via sudo with the original user's audit UID (auid). The auid persists even after su/sudo, allowing you to trace who actually ran a command.",
            "mitre": ["T1548.003"]
        },
        {
            "id": "ANOM_ABEND",
            "name": "Abnormal Process Termination",
            "description": "A process terminated abnormally (segfault, SIGKILL). May indicate exploit attempts (buffer overflow crashes), or an attacker killing security processes.",
            "mitre": ["T1203", "T1489"]
        },
        {
            "id": "CONFIG_CHANGE",
            "name": "Audit Configuration Changed",
            "description": "The audit rules or configuration were modified. Attackers modify audit rules to stop logging their activity — this event should trigger an alert even in maintenance windows.",
            "mitre": ["T1562.001"]
        },
        {
            "id": "MAC_POLICY_LOAD",
            "name": "SELinux/AppArmor Policy Changed",
            "description": "Mandatory Access Control policy was loaded or modified. Attackers may disable SELinux (setenforce 0) or modify AppArmor profiles to bypass security restrictions.",
            "mitre": ["T1562.001"]
        }
    ]
},

"Linux bash history": {
    "description": "Bash history records every command typed by users in interactive bash sessions. While easily tampered with (attackers can clear it), when preserved it provides a direct record of attacker commands during an intrusion. It is the simplest form of command logging but should NOT be relied upon as the sole source — use auditd EXECVE logging as the authoritative command log.",
    "detection_value": "medium",
    "log_path": "~/.bash_history (per-user, typically /home/<user>/.bash_history and /root/.bash_history)",
    "log_channel": "bash shell history (file-based)",
    "prerequisites": [
        "HISTFILE environment variable must not be unset (attackers run 'unset HISTFILE' to stop logging)",
        "HISTSIZE and HISTFILESIZE should be set to large values (10000+) in /etc/profile or /etc/bash.bashrc",
        "Set HISTTIMEFORMAT='%F %T ' in /etc/profile to add timestamps to history entries",
        "Consider setting HISTCONTROL='' (empty) to log duplicate and space-prefixed commands",
        "Make history file append-only: chattr +a ~/.bash_history (prevents clearing)",
        "For reliable command logging, deploy auditd with EXECVE rules instead of relying on bash history",
        "Wazuh agent can monitor bash_history files via the syscheck (FIM) module"
    ],
    "key_fields": [
        "command", "timestamp (if HISTTIMEFORMAT set)", "user (inferred from file path)"
    ],
    "critical_event_ids": [
        {
            "id": "recon_commands",
            "name": "Reconnaissance Commands",
            "description": "Commands like whoami, id, uname -a, cat /etc/passwd, ifconfig, ip addr, netstat, ss, ps aux, df -h. These are typically the first commands an attacker runs after gaining access to understand the environment.",
            "mitre": ["T1033", "T1082", "T1016", "T1049"]
        },
        {
            "id": "download_commands",
            "name": "Download/Transfer Commands",
            "description": "Commands like wget, curl, scp, nc (netcat), python -m http.server, fetch. Indicate an attacker downloading tools, malware, or exfiltrating data from the compromised host.",
            "mitre": ["T1105", "T1041"]
        },
        {
            "id": "persistence_commands",
            "name": "Persistence Commands",
            "description": "Commands like crontab -e, systemctl enable, echo >> .bashrc, echo >> /etc/cron.d/. Indicate an attacker establishing persistent access mechanisms.",
            "mitre": ["T1053.003", "T1543.002", "T1546.004"]
        },
        {
            "id": "priv_esc_commands",
            "name": "Privilege Escalation Commands",
            "description": "Commands like sudo, su, find / -perm -4000 (SUID search), chmod +s, capabilities enumeration. Indicate an attacker attempting to escalate privileges.",
            "mitre": ["T1548.001", "T1548.003"]
        },
        {
            "id": "defense_evasion",
            "name": "Anti-Forensics Commands",
            "description": "Commands like history -c, unset HISTFILE, rm ~/.bash_history, shred, echo '' > /var/log/auth.log. Direct indicators that an attacker is actively covering their tracks.",
            "mitre": ["T1070.003", "T1070.004"]
        },
        {
            "id": "lateral_movement",
            "name": "Lateral Movement Commands",
            "description": "Commands like ssh user@host, scp file host:, rsync, psexec, wmic. Indicate the attacker is moving to other systems in the network.",
            "mitre": ["T1021.004", "T1570"]
        }
    ]
},

# ═══════════════════════════════════════════════════════════════════════════════
#  IDENTITY SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

"Okta System Log": {
    "description": "The Okta System Log captures all authentication, authorization, and administrative events across your Okta identity platform. As the central identity provider for many organizations, Okta logs are critical for detecting account compromise, MFA bypass, phishing-based credential theft, and unauthorized administrative changes.",
    "detection_value": "critical",
    "log_path": "Okta Admin Console → Reports → System Log (or via /api/v1/logs API endpoint)",
    "log_channel": "Okta System Log API",
    "prerequisites": [
        "Okta organization must be provisioned and configured as the identity provider",
        "API token must be created with Read-Only Admin or Report Admin permissions for log collection",
        "SIEM integration must be configured (Okta → Okta Integration Network → SIEM connector, or poll /api/v1/logs)",
        "Event hooks can be configured for real-time alerting on critical events",
        "Ensure all Okta policies (sign-on, MFA, password) are configured to generate audit events",
        "Wazuh or your SIEM must have an Okta integration module or custom decoder"
    ],
    "key_fields": [
        "eventType", "actor.displayName", "actor.alternateId", "client.ipAddress",
        "client.geographicalContext", "client.userAgent", "outcome.result",
        "outcome.reason", "target[].displayName", "target[].type",
        "authenticationContext.authenticationProvider", "debugContext.debugData"
    ],
    "critical_event_ids": [
        {
            "id": "user.session.start",
            "name": "User Login",
            "description": "User successfully authenticated to Okta. Check client IP, geolocation, and user agent. Logins from unusual locations, new devices, or via VPN/Tor are high priority.",
            "mitre": ["T1078", "T1078.004"]
        },
        {
            "id": "user.authentication.auth_via_mfa",
            "name": "MFA Verification",
            "description": "MFA challenge was presented and completed. Track MFA type (push, TOTP, SMS). A burst of MFA push notifications may indicate MFA fatigue attack.",
            "mitre": ["T1621"]
        },
        {
            "id": "user.account.lock",
            "name": "Account Locked",
            "description": "User account was locked due to excessive failed attempts. Indicates brute force or credential stuffing attack against that specific user.",
            "mitre": ["T1110"]
        },
        {
            "id": "policy.evaluate_sign_on",
            "name": "Sign-On Policy Evaluated",
            "description": "Okta evaluated sign-on policies for a login attempt. Policy denials from unexpected contexts reveal reconnaissance and blocked attack attempts.",
            "mitre": ["T1078"]
        },
        {
            "id": "user.mfa.factor.deactivate",
            "name": "MFA Factor Removed",
            "description": "An MFA factor was removed from a user's account. If not initiated by the user or IT, this indicates an attacker removing MFA to maintain access without the second factor.",
            "mitre": ["T1556"]
        },
        {
            "id": "user.account.privilege.grant",
            "name": "Admin Privilege Granted",
            "description": "Administrative privileges were assigned to a user. Unauthorized privilege escalation in the identity provider gives an attacker control over all connected applications.",
            "mitre": ["T1098.003"]
        },
        {
            "id": "application.user_membership.add",
            "name": "User Added to Application",
            "description": "A user was granted access to an application. Unauthorized application access grants may indicate an attacker expanding their access to sensitive systems.",
            "mitre": ["T1098"]
        }
    ]
},

"Azure AD Sign-in Log": {
    "description": "Azure Active Directory (Entra ID) Sign-in Logs capture all authentication events for Microsoft 365, Azure resources, and federated applications. They include Conditional Access policy results, MFA status, risk detections, and device compliance — providing the richest authentication context of any identity provider log.",
    "detection_value": "critical",
    "log_path": "Azure Portal → Azure Active Directory → Sign-in logs (or via Microsoft Graph API /auditLogs/signIns)",
    "log_channel": "Azure AD / Microsoft Graph API",
    "prerequisites": [
        "Azure AD Premium P1 or P2 license required for full sign-in log access and retention beyond 7 days",
        "Diagnostic Settings must be configured to export logs to a SIEM (via Event Hub, Storage Account, or Log Analytics)",
        "Conditional Access policies should be configured to generate rich evaluation data",
        "Azure AD Identity Protection should be enabled for risk-based detections (requires P2)",
        "Named Locations should be configured so geographic anomalies are properly flagged",
        "Service Principal and Managed Identity sign-ins require separate log configuration"
    ],
    "key_fields": [
        "userPrincipalName", "appDisplayName", "ipAddress", "location",
        "clientAppUsed", "deviceDetail", "status.errorCode", "status.failureReason",
        "conditionalAccessStatus", "mfaDetail", "riskLevelAggregated",
        "riskLevelDuringSignIn", "riskState", "isInteractive", "resourceDisplayName"
    ],
    "critical_event_ids": [
        {
            "id": "Sign-in:Success",
            "name": "Successful Sign-in",
            "description": "User successfully authenticated. Check location, device, app, and whether MFA was satisfied. Impossible travel (login from two distant locations in short time) is a key detection.",
            "mitre": ["T1078", "T1078.004"]
        },
        {
            "id": "Sign-in:Failure:50126",
            "name": "Invalid Password",
            "description": "Error code 50126 means invalid username or password. High volumes indicate password spray attacks — especially if spread across many accounts from few IPs.",
            "mitre": ["T1110.003"]
        },
        {
            "id": "Sign-in:Failure:50053",
            "name": "Account Locked",
            "description": "Error code 50053 — account is locked due to too many failed sign-in attempts. Active brute force indicator.",
            "mitre": ["T1110"]
        },
        {
            "id": "Sign-in:Failure:50074",
            "name": "MFA Required",
            "description": "Error code 50074 — strong authentication (MFA) is required but was not completed. May indicate stolen credentials where the attacker cannot complete MFA.",
            "mitre": ["T1078"]
        },
        {
            "id": "Sign-in:Legacy_Auth",
            "name": "Legacy Authentication Protocol",
            "description": "Sign-in using legacy protocols (POP3, IMAP, SMTP, ActiveSync) which bypass MFA. Attackers specifically target legacy auth to avoid MFA enforcement. These should be blocked by Conditional Access.",
            "mitre": ["T1078", "T1550"]
        },
        {
            "id": "Sign-in:Risky",
            "name": "Risk Detection Triggered",
            "description": "Azure AD Identity Protection flagged the sign-in as risky (anonymous IP, malware-linked IP, unfamiliar sign-in properties, impossible travel). These detections combine Microsoft's threat intelligence with behavioral analysis.",
            "mitre": ["T1078"]
        },
        {
            "id": "ConditionalAccess:Failure",
            "name": "Conditional Access Blocked",
            "description": "A Conditional Access policy blocked the sign-in attempt. Shows what the policy required and why the attempt failed — useful for verifying policy effectiveness and detecting policy bypass attempts.",
            "mitre": ["T1078"]
        }
    ]
},

"OneLogin Event Log": {
    "description": "OneLogin Event Logs capture authentication, provisioning, and administrative events across the OneLogin identity platform. As a single sign-on (SSO) provider, OneLogin events reveal credential compromise, unauthorized app access, and administrative changes that affect the entire connected application ecosystem.",
    "detection_value": "high",
    "log_path": "OneLogin Admin Console → Activity → Events (or via /api/1/events API endpoint)",
    "log_channel": "OneLogin Events API",
    "prerequisites": [
        "OneLogin account with admin access for log review and API token creation",
        "API credentials must be generated (Developers → API Credentials) for SIEM integration",
        "Event Broadcasting should be enabled for real-time event streaming to your SIEM",
        "Trusted IdP configurations must be reviewed to ensure all auth events are captured",
        "Wazuh or your SIEM needs a OneLogin integration or custom log decoder"
    ],
    "key_fields": [
        "event_type_id", "user_name", "actor_user_name", "ipaddr",
        "app_name", "account_id", "notes", "error_description",
        "resolution", "risk_score", "otp_device_name"
    ],
    "critical_event_ids": [
        {
            "id": "5",
            "name": "Login Success",
            "description": "Successful user login to OneLogin portal. Check IP address and whether MFA was used. Correlate with known user locations and typical access patterns.",
            "mitre": ["T1078", "T1078.004"]
        },
        {
            "id": "6",
            "name": "Login Failed",
            "description": "Failed login attempt. Multiple failures for the same account indicate targeted attack. Failures across many accounts from one IP indicate password spray.",
            "mitre": ["T1110"]
        },
        {
            "id": "8",
            "name": "User Assumed Another User",
            "description": "An admin assumed the identity of another user (impersonation). While legitimate for support, unauthorized assumption indicates admin account compromise.",
            "mitre": ["T1134"]
        },
        {
            "id": "52",
            "name": "MFA Factor Registered",
            "description": "A new MFA device was registered for a user. Unauthorized MFA enrollment by an attacker with stolen credentials allows them to maintain access with their own MFA device.",
            "mitre": ["T1556"]
        },
        {
            "id": "72",
            "name": "User Provisioned to App",
            "description": "A user was provisioned access to an application. Unauthorized provisioning grants attacker access to sensitive connected applications like email, cloud storage, or financial systems.",
            "mitre": ["T1098"]
        }
    ]
},

"Cisco Duo Log": {
    "description": "Cisco Duo authentication logs capture every MFA challenge, enrollment event, and administrative action across your Duo-protected applications. Since Duo is typically the MFA layer sitting in front of VPNs, email, and critical applications, these logs are essential for detecting MFA bypass, push notification abuse, and authentication anomalies.",
    "detection_value": "high",
    "log_path": "Duo Admin Panel → Reports → Authentication Log (or via Admin API /admin/v2/logs/authentication)",
    "log_channel": "Duo Admin API",
    "prerequisites": [
        "Duo account with Admin API application enabled for log collection",
        "Admin API integration key, secret key, and API hostname must be configured in your SIEM",
        "Authentication log retention is 180 days in Duo (export regularly for longer retention)",
        "Duo Beyond or Duo Access edition recommended for device trust and risk-based features",
        "Wazuh or your SIEM needs a Duo integration module or custom decoder"
    ],
    "key_fields": [
        "timestamp", "username", "factor", "result", "reason",
        "ip", "integration", "new_enrollment", "device",
        "location.city", "location.country", "access_device.os",
        "auth_device.name", "event_type", "adaptive_trust_assessments"
    ],
    "critical_event_ids": [
        {
            "id": "auth:success",
            "name": "Authentication Success",
            "description": "User successfully completed Duo MFA challenge. Check the factor used (push, phone, SMS, hardware token), the IP, and the application. Unusual apps or locations are suspicious.",
            "mitre": ["T1078"]
        },
        {
            "id": "auth:denied",
            "name": "Authentication Denied",
            "description": "Duo denied the authentication — user pressed 'Deny' on push, entered wrong passcode, or policy blocked access. Multiple denials may indicate the user is receiving unauthorized push requests (MFA fatigue attack).",
            "mitre": ["T1621"]
        },
        {
            "id": "auth:fraud",
            "name": "Fraud Reported",
            "description": "User pressed the 'fraud' button on a Duo push notification they did not initiate. This is a confirmed indicator that someone is attempting to authenticate with the user's stolen credentials.",
            "mitre": ["T1621", "T1078"]
        },
        {
            "id": "enrollment",
            "name": "New Device Enrolled",
            "description": "A new device was enrolled for Duo MFA. If the user did not initiate enrollment, an attacker with stolen credentials is registering their own device to bypass MFA.",
            "mitre": ["T1556", "T1098"]
        },
        {
            "id": "bypass_status:enabled",
            "name": "Bypass Status Enabled",
            "description": "A user's bypass status was enabled, allowing them to skip MFA. If not authorized by IT, an admin account may be compromised. This effectively disables MFA for the target user.",
            "mitre": ["T1556"]
        },
        {
            "id": "admin_action",
            "name": "Admin Action Logged",
            "description": "Administrative action in the Duo Admin Panel (user creation, policy changes, integration modifications). Unauthorized admin actions indicate admin account compromise with full control over the MFA infrastructure.",
            "mitre": ["T1098"]
        }
    ]
}

}  # end DETAILS


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    db_path = os.path.join(project_root, 'detection_platform.db')

    if not os.path.exists(db_path):
        print(f"ERROR: Database not found at {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Ensure details column exists
    cols = {r[1] for r in c.execute("PRAGMA table_info(telemetry_sources)").fetchall()}
    if "details" not in cols:
        c.execute("ALTER TABLE telemetry_sources ADD COLUMN details TEXT")
        print("Added 'details' column to telemetry_sources")

    # Update each source
    updated = 0
    skipped = 0
    for name, detail_data in DETAILS.items():
        c.execute("SELECT source_id FROM telemetry_sources WHERE name = ?", (name,))
        row = c.fetchone()
        if row:
            detail_json = json.dumps(detail_data, ensure_ascii=False)
            c.execute("UPDATE telemetry_sources SET details = ? WHERE source_id = ?",
                      (detail_json, row[0]))
            evt_count = len(detail_data.get("critical_event_ids", []))
            print(f"  ✓ {name}: {evt_count} Event IDs, value={detail_data['detection_value']}")
            updated += 1
        else:
            print(f"  ✗ {name}: NOT FOUND in database — skipped")
            skipped += 1

    conn.commit()
    conn.close()

    total_events = sum(len(d.get("critical_event_ids", [])) for d in DETAILS.values())
    print(f"\n{'='*50}")
    print(f"DONE: {updated} sources updated, {skipped} skipped")
    print(f"Total Event IDs documented: {total_events}")
    print(f"{'='*50}")
    print(f"\nRestart the server and refresh the Telemetry page.")
    print(f"Each card should now show event count and 'View Full Details' link.")


if __name__ == "__main__":
    main()