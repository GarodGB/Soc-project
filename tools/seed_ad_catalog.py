"""
ABSEGA - seed the NEW Active Directory attack catalog (idempotent, UPSERT).

- Runs AFTER migrate_004_ad_catalog.py (needs the new columns).
- Uses stable attack keys (test_id). Re-running refreshes the *definition*
  fields but never duplicates a row and never touches runs / evidence /
  comparisons that reference these test_ids.
- Does NOT redefine the original 6 attacks (encoded PS, kerberoast, asrep,
  smb-spray, ldap-spray, psexec). Those keep their existing rows.

Support modes:  automatic | assisted | manual_only | safe_emulation_only
Prereq status:  ready | partially_ready | blocked_by_prerequisite | unknown

Candidate Wazuh / Sigma rule lists are intentionally left empty: the platform
resolves candidates from the REAL normalized evidence at compare time
(content_compare + sigma_eval). Pre-filling rule IDs by title/tag would be the
exact "mapping != detection" mistake the project forbids.

Usage (from project root):
    python seed_ad_catalog.py
    python seed_ad_catalog.py --db detection_platform.db
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from app.database import get_connection

SEED_VERSION = 1
DC = "DC01"
WS = "WIN11"

# Each tuple field is explicit for auditability.
# key, name, desc, technique, tactic, category, stage, src, dst, privs,
# prereqs[], tools[], channels[], event_ids[], sysmon_ids[], protocols[],
# wazuh_telemetry[], fp_notes, support_mode, prereq_status, risk,
# sim_cmd, cleanup_cmd, rollback, telemetry_components[]
ATTACKS: list[dict] = [
    dict(
        key="AD-T1003.006-DCSYNC", name="DCSync replication abuse",
        desc="Abuse directory replication (DS-Replication-Get-Changes / -All) to pull "
             "password hashes from DC01 without touching NTDS.dit on disk.",
        technique="T1003.006", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="Account holding Replicating Directory Changes (All) rights, or Domain Admin",
        prereqs=["Account with DS-Replication-Get-Changes-All on the domain head",
                 "Directory Service Access auditing enabled on DC01"],
        tools=["mimikatz lsadump::dcsync", "impacket-secretsdump"],
        channels=["Security"], event_ids=["4662"], sysmon_ids=["3"],
        protocols=["DRSUAPI/RPC", "TCP/135", "TCP/49152-65535"],
        wazuh_telemetry=["Security 4662 with replication property GUIDs", "wazuh archives"],
        fp="4662 is high-volume on a DC; only replication-GUID access "
           "(1131f6aa-.. / 1131f6ad-..) from a non-DC principal is suspicious. "
           "Legit DCs replicate constantly - filter by source host = DC.",
        support="assisted", prereq="partially_ready", risk="high",
        sim="From WIN11, run secretsdump/mimikatz dcsync for a single lab account "
            "(e.g. krbtgt in the isolated lab) to generate 4662 replication access.",
        cleanup="No object change; rotate any credential exposed. Review 4662 baseline.",
        rollback="None required (read-only), but treat exposed hashes as burned in lab.",
        tcs=["ds_access_audit", "object_access_audit", "wazuh_archives", "sysmon_operational"],
    ),
    dict(
        key="AD-T1003.003-NTDS-EXTRACT", name="NTDS.dit credential extraction",
        desc="Extract the NTDS.dit database + SYSTEM hive via VSS/ntdsutil on DC01 to "
             "recover all domain credentials offline.",
        technique="T1003.003", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=DC, dst=DC,
        privs="Local admin / Domain Admin on DC01",
        prereqs=["Local admin on DC01", "Process-creation-with-cmdline auditing",
                 "Sysmon on DC01"],
        tools=["ntdsutil", "vssadmin", "esentutl"],
        channels=["Security", "System", "Microsoft-Windows-Sysmon/Operational",
                  "Microsoft-Windows-PowerShell/Operational"],
        event_ids=["4688", "8222"], sysmon_ids=["1", "11"],
        protocols=["Local"],
        wazuh_telemetry=["4688 command line for ntdsutil/vssadmin", "Sysmon 1 process create",
                         "Sysmon 11 file create for the dumped .dit"],
        fp="ntdsutil/vssadmin have legitimate backup uses; correlate cmdline "
           "('create full', 'ac i ntds', 'ifm') + output path + operator account.",
        support="assisted", prereq="ready", risk="high",
        sim="On DC01 run ntdsutil 'ac i ntds' 'ifm' 'create full C:\\lab_ifm' to a "
            "temp path; capture 4688/Sysmon-1; delete the export.",
        cleanup="Delete C:\\lab_ifm and any VSS snapshot created; vssadmin delete shadows.",
        rollback="Snapshot DC01 before test; delete dumped files immediately after.",
        tcs=["process_creation_cmdline", "sysmon_operational", "system_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1550.002-PTH", name="Pass-the-Hash",
        desc="Authenticate to a domain host using an NTLM hash instead of a plaintext "
             "password (over-pass or classic PtH).",
        technique="T1550.002", tactic="Lateral Movement", category="Lateral Movement",
        stage="Lateral Movement", src=WS, dst=DC,
        privs="A captured NTLM hash of a domain account",
        prereqs=["A recovered NTLM hash for a lab account", "Credential Validation auditing"],
        tools=["mimikatz sekurlsa::pth", "impacket (smbexec/wmiexec -hashes)"],
        channels=["Security", "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["4624", "4672", "4776"], sysmon_ids=["1", "10"],
        protocols=["SMB", "NTLM", "TCP/445"],
        wazuh_telemetry=["4624 LogonType 9 (NewCredentials)", "4776 NTLM validation",
                         "Sysmon 10 LSASS access on source"],
        fp="LogonType 9 also appears with runas /netonly; correlate with source "
           "process (Sysmon 10 to lsass) and unusual target/account pairing.",
        support="assisted", prereq="partially_ready", risk="high",
        sim="Use a lab account hash to authenticate WIN11 -> DC01 once; capture 4624/4776.",
        cleanup="None (auth only). Rotate the account credential used.",
        rollback="None required.",
        tcs=["credential_validation", "security_log", "sysmon_operational", "wazuh_archives"],
    ),
    dict(
        key="AD-T1550.003-PTT", name="Pass-the-Ticket",
        desc="Inject a stolen/forged Kerberos TGT or service ticket into the current "
             "session to access resources as the ticket owner.",
        technique="T1550.003", tactic="Lateral Movement", category="Lateral Movement",
        stage="Lateral Movement", src=WS, dst=DC,
        privs="A valid or forged Kerberos ticket (.kirbi)",
        prereqs=["A ticket to inject (Rubeus dump or forged)", "Kerberos auditing on DC01"],
        tools=["Rubeus ptt", "mimikatz kerberos::ptt"],
        channels=["Security"], event_ids=["4768", "4769", "4624"], sysmon_ids=["1"],
        protocols=["Kerberos", "TCP/88"],
        wazuh_telemetry=["4769 service ticket use without matching 4768",
                         "4624 logon following ticket injection"],
        fp="Ticket reuse is subtle; look for 4769 with no preceding 4768 for the "
           "same client, or tickets used from an unexpected host.",
        support="assisted", prereq="ready", risk="high",
        sim="With Rubeus: dump a lab ticket, then 'ptt' it and access DC01 share once.",
        cleanup="klist purge on WIN11.",
        rollback="None required.",
        tcs=["kerberos_audit", "security_log", "sysmon_operational", "wazuh_archives"],
    ),
    dict(
        key="AD-T1558.001-GOLDEN", name="Golden Ticket",
        desc="Forge a KRBTGT-signed TGT granting arbitrary domain access; survives "
             "password resets of the impersonated user.",
        technique="T1558.001", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="KRBTGT account hash (obtained via DCSync/NTDS)",
        prereqs=["KRBTGT hash", "Kerberos auditing", "SNAPSHOT of DC01 before test"],
        tools=["mimikatz kerberos::golden", "Rubeus golden"],
        channels=["Security"], event_ids=["4769", "4624", "4672"], sysmon_ids=[],
        protocols=["Kerberos", "TCP/88"],
        wazuh_telemetry=["4769 with anomalous ticket lifetime / encryption",
                         "4624/4672 for a principal with no 4768"],
        fp="Hard to detect from a single event; requires correlation (RC4 tickets, "
           "impossible lifetimes, missing AS-REQ). Baseline required.",
        support="manual_only", prereq="partially_ready", risk="critical",
        sim="MANUAL ONLY: forge a short-lifetime golden ticket for a throwaway lab "
            "principal, use once, then purge. Never for a real privileged account.",
        cleanup="klist purge; reset KRBTGT twice after the lab exercise.",
        rollback="Requires KRBTGT double-reset; snapshot DC01 first. Destructive if misused.",
        tcs=["kerberos_audit", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1558.002-SILVER", name="Silver Ticket",
        desc="Forge a service-account-signed TGS for a specific SPN, bypassing the DC "
             "entirely for that service.",
        technique="T1558.002", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="Target service account hash (e.g. machine account or svc)",
        prereqs=["Service account hash", "Object Access / Kerberos auditing on target"],
        tools=["mimikatz kerberos::golden /service", "Rubeus silver"],
        channels=["Security"], event_ids=["4624", "4634"], sysmon_ids=[],
        protocols=["Kerberos", "SMB/CIFS"],
        wazuh_telemetry=["Service access (4624) on target with NO corresponding 4769 on DC"],
        fp="Detection depends on absence of a DC 4769 for a service access that "
           "occurred - requires cross-host correlation.",
        support="manual_only", prereq="partially_ready", risk="high",
        sim="MANUAL ONLY: forge a TGS for a lab service SPN, access it once, purge.",
        cleanup="klist purge; rotate the service account password.",
        rollback="Rotate affected service account credential.",
        tcs=["kerberos_audit", "object_access_audit", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1552.006-GPP-CPASSWORD", name="GPP cPassword discovery",
        desc="Recover the AES-encrypted cPassword from legacy Group Policy Preferences "
             "XML in SYSVOL (key is public).",
        technique="T1552.006", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="Any authenticated domain user (SYSVOL is world-readable)",
        prereqs=["A GPP XML containing cpassword planted in SYSVOL (lab setup)",
                 "Object Access auditing on SYSVOL (optional)"],
        tools=["Get-GPPPassword (PowerSploit)", "gpp-decrypt", "findstr cpassword"],
        channels=["Security"], event_ids=["4663", "5145"], sysmon_ids=["3", "11"],
        protocols=["SMB", "TCP/445"],
        fp="SYSVOL reads are extremely common; only reads of *.xml containing "
           "'cpassword' by a normal user are notable. Needs file-name context.",
        wazuh_telemetry=["5145 network share access to SYSVOL", "4663 file read on Groups.xml"],
        support="assisted", prereq="partially_ready", risk="medium",
        sim="Plant a lab Groups.xml with a cpassword in SYSVOL, then read it from WIN11.",
        cleanup="Remove the planted Groups.xml from SYSVOL.",
        rollback="Delete the lab GPP file.",
        tcs=["object_access_audit", "sysmon_operational", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1087.002-SHARPHOUND", name="SharpHound / BloodHound collection",
        desc="Mass LDAP + SMB enumeration of users, groups, sessions, ACLs and trusts "
             "for attack-path mapping.",
        technique="T1087.002", tactic="Discovery", category="Discovery",
        stage="Discovery", src=WS, dst=DC,
        privs="Any authenticated domain user",
        prereqs=["Authenticated domain user", "LDAP diagnostic (1644) or DS Access auditing"],
        tools=["SharpHound.exe", "bloodhound-python", "AzureHound"],
        channels=["Security", "Directory Service", "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["4662", "1644"], sysmon_ids=["1", "3"],
        protocols=["LDAP", "SMB", "TCP/389", "TCP/445"],
        wazuh_telemetry=["Burst of 4662/1644 LDAP reads", "Sysmon 3 many short-lived "
                         "connections", "Sysmon 1 collector process"],
        fp="Individual LDAP reads are normal; the signal is VOLUME + breadth in a "
           "short window from one host. Requires thresholding/correlation.",
        support="assisted", prereq="partially_ready", risk="medium",
        sim="Run SharpHound '-c All' from WIN11 against absega.local; collect the burst.",
        cleanup="Delete collected .zip/.json output on WIN11.",
        rollback="None (read-only).",
        tcs=["ds_access_audit", "ldap_diagnostics", "sysmon_operational", "wazuh_archives"],
    ),
    dict(
        key="AD-T1087.002-KERB-ENUM", name="Kerberos user enumeration",
        desc="Enumerate valid domain usernames via Kerberos pre-auth responses "
             "(KDC_ERR_C_PRINCIPAL_UNKNOWN vs PREAUTH_REQUIRED).",
        technique="T1087.002", tactic="Discovery", category="Discovery",
        stage="Discovery", src=WS, dst=DC,
        privs="Network access to the KDC (no credentials needed)",
        prereqs=["Kerberos auditing (4768) enabled on DC01"],
        tools=["Kerbrute userenum", "Rubeus"],
        channels=["Security"], event_ids=["4768", "4771"], sysmon_ids=["3"],
        protocols=["Kerberos", "UDP/88", "TCP/88"],
        wazuh_telemetry=["Many 4768 with failure code 0x6 (unknown principal) from one host"],
        fp="A few 4768 failures are normal (typos); the signal is many distinct "
           "usernames failing 0x6 from one source in a short window.",
        support="assisted", prereq="ready", risk="low",
        sim="Run kerbrute userenum with a small lab wordlist against DC01.",
        cleanup="None.",
        rollback="None.",
        tcs=["kerberos_audit", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1087.002-LDAP-RECON", name="LDAP domain reconnaissance",
        desc="Direct LDAP queries (PowerView / ldapsearch) to enumerate users, groups, "
             "GPOs, ACLs and delegation settings.",
        technique="T1087.002", tactic="Discovery", category="Discovery",
        stage="Discovery", src=WS, dst=DC,
        privs="Any authenticated domain user",
        prereqs=["LDAP field-engine diagnostic logging (1644) for full fidelity"],
        tools=["PowerView", "ldapsearch", "AD PowerShell module"],
        channels=["Directory Service", "Security"], event_ids=["1644", "4662"],
        sysmon_ids=["3"], protocols=["LDAP", "TCP/389", "TCP/636"],
        wazuh_telemetry=["1644 expensive/inefficient LDAP searches", "4662 property reads"],
        fp="LDAP recon overlaps heavily with admin tooling; needs query-pattern "
           "and volume context, not single events.",
        support="assisted", prereq="partially_ready", risk="low",
        sim="Run a broad PowerView Get-DomainUser/Get-DomainGroup sweep from WIN11.",
        cleanup="None.",
        rollback="None.",
        tcs=["ldap_diagnostics", "ds_access_audit", "wazuh_archives"],
    ),
    dict(
        key="AD-T1098-RBCD", name="Resource-Based Constrained Delegation abuse",
        desc="Write msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer to "
             "impersonate arbitrary users to its services (S4U).",
        technique="T1098", tactic="Privilege Escalation", category="Privilege Escalation",
        stage="Privilege Escalation", src=WS, dst=DC,
        privs="WriteProperty on the target computer object (or GenericWrite)",
        prereqs=["Control over target computer object's msDS-AllowedToActOnBehalf...",
                 "Directory Service Changes auditing (5136)"],
        tools=["PowerView Set-ADComputer", "Rubeus s4u", "impacket rbcd.py"],
        channels=["Security"], event_ids=["5136", "4769"], sysmon_ids=[],
        protocols=["LDAP", "Kerberos"],
        wazuh_telemetry=["5136 modify of msDS-AllowedToActOnBehalfOfOtherIdentity",
                         "4769 S4U2Proxy tickets"],
        fp="Delegation attribute writes are rare and privileged; low FP if you key "
           "on the specific attribute + non-admin initiator.",
        support="assisted", prereq="ready", risk="high",
        sim="Set msDS-AllowedToActOnBehalfOfOtherIdentity on a lab computer object; "
            "capture 5136; then remove it.",
        cleanup="Clear the delegation attribute on the target object.",
        rollback="Reset msDS-AllowedToActOnBehalfOfOtherIdentity to empty.",
        tcs=["ds_changes_audit", "kerberos_audit", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1134.005-SIDHISTORY", name="SID History injection",
        desc="Inject a privileged SID into an account's sIDHistory to inherit its "
             "access without group membership.",
        technique="T1134.005", tactic="Privilege Escalation", category="Privilege Escalation",
        stage="Privilege Escalation", src=DC, dst=DC,
        privs="Domain Admin / DSRM or mimikatz sid::patch on DC",
        prereqs=["DA-level control or DCSync", "DS Changes auditing (5136) + 4765/4766"],
        tools=["mimikatz sid::add", "DSInternals Add-ADDBSidHistory"],
        channels=["Security"], event_ids=["4765", "4766", "5136"], sysmon_ids=[],
        protocols=["LDAP", "DRSUAPI"],
        wazuh_telemetry=["4765 SID History added to an account", "5136 sIDHistory modify"],
        fp="4765 is inherently rare; almost always suspicious outside a real migration.",
        support="assisted", prereq="partially_ready", risk="high",
        sim="Add a benign lab SID to a throwaway account's sIDHistory; capture 4765/5136; remove.",
        cleanup="Remove the injected SID from sIDHistory.",
        rollback="Clear sIDHistory on the affected account; snapshot DC01 first.",
        tcs=["ds_changes_audit", "account_management", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1098-ADMINSDHOLDER", name="AdminSDHolder persistence",
        desc="Modify the AdminSDHolder ACL so SDProp re-applies attacker rights to all "
             "protected (admin) accounts hourly.",
        technique="T1098", tactic="Persistence", category="Persistence",
        stage="Persistence", src=WS, dst=DC,
        privs="WriteDACL on CN=AdminSDHolder,CN=System,<domain>",
        prereqs=["Write access to AdminSDHolder", "DS Changes auditing (5136) + 4662"],
        tools=["PowerView Add-DomainObjectAcl", "dsacls"],
        channels=["Security"], event_ids=["5136", "4662"], sysmon_ids=[],
        protocols=["LDAP"],
        wazuh_telemetry=["5136/4662 modify of the AdminSDHolder object DACL"],
        fp="AdminSDHolder changes are extremely rare; near-zero FP when keyed on the "
           "object DN.",
        support="assisted", prereq="ready", risk="high",
        sim="Add a benign ACE to AdminSDHolder for a lab user; capture 5136; then revert.",
        cleanup="Remove the added ACE; let SDProp re-normalize.",
        rollback="Restore original AdminSDHolder DACL (snapshot first).",
        tcs=["ds_changes_audit", "ds_access_audit", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1098-DA-MEMBERSHIP", name="Domain Admins membership modification",
        desc="Add an unauthorized principal to a highly-privileged group (Domain "
             "Admins / Enterprise Admins / Administrators).",
        technique="T1098", tactic="Persistence", category="Persistence",
        stage="Persistence", src=WS, dst=DC,
        privs="Write membership on the target privileged group",
        prereqs=["Security Group Management auditing (4728/4756)"],
        tools=["net group", "Add-ADGroupMember", "PowerView"],
        channels=["Security"], event_ids=["4728", "4732", "4756"], sysmon_ids=[],
        protocols=["LDAP", "SAMR"],
        wazuh_telemetry=["4728 member added to global group (Domain Admins)",
                         "4756 added to universal group (Enterprise Admins)"],
        fp="Legit admin onboarding also fires 4728; key on target group = Domain/"
           "Enterprise Admins + initiator not on an allowlist.",
        support="assisted", prereq="ready", risk="high",
        sim="Add a lab user to Domain Admins; capture 4728; then remove it.",
        cleanup="Remove the user from the privileged group.",
        rollback="Remove added membership immediately.",
        tcs=["group_management", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1136.002-PRIV-USER-CREATE", name="Suspicious privileged user creation",
        desc="Create a new domain account and immediately elevate it (create + add to "
             "privileged group) as a persistence foothold.",
        technique="T1136.002", tactic="Persistence", category="Persistence",
        stage="Persistence", src=WS, dst=DC,
        privs="Account creation + group write rights",
        prereqs=["User Account Management + Group Management auditing"],
        tools=["net user /add /domain", "New-ADUser"],
        channels=["Security"], event_ids=["4720", "4722", "4724", "4728"], sysmon_ids=[],
        protocols=["LDAP", "SAMR"],
        wazuh_telemetry=["4720 account created THEN 4728 added to privileged group "
                         "within a short window (correlation)"],
        fp="Account creation alone is routine; the correlated create->privilege "
           "sequence by a non-provisioning account is the signal.",
        support="assisted", prereq="ready", risk="medium",
        sim="net user labpersist /add /domain, then add to a group; capture 4720+4728; delete.",
        cleanup="Delete the created account.",
        rollback="Remove the created account and any group membership.",
        tcs=["account_management", "group_management", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1558.003-TARGETED-SPN", name="Targeted SPN set + Kerberoast",
        desc="Write an SPN onto a user account you control, then Kerberoast it - "
             "turning any writable user into a roastable target.",
        technique="T1558.003", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="GenericWrite/WriteProperty (servicePrincipalName) on the target user",
        prereqs=["Write access to a user's servicePrincipalName",
                 "DS Changes auditing (5136) + Kerberos auditing (4769)"],
        tools=["PowerView Set-DomainObject", "Rubeus kerberoast"],
        channels=["Security"], event_ids=["5136", "4769"], sysmon_ids=[],
        protocols=["LDAP", "Kerberos"],
        wazuh_telemetry=["5136 servicePrincipalName added to a user THEN 4769 RC4 (0x17) "
                         "for that SPN (correlation)"],
        fp="Distinguished from normal Kerberoast by the preceding SPN write; key on "
           "5136 servicePrincipalName + subsequent 4769 for the same object.",
        support="assisted", prereq="ready", risk="medium",
        sim="Set an SPN on a lab user, roast it with Rubeus, then clear the SPN.",
        cleanup="Remove the added servicePrincipalName from the user.",
        rollback="Clear the injected SPN.",
        tcs=["ds_changes_audit", "kerberos_audit", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1098-PASSWORD-RESET", name="Malicious account password reset",
        desc="Reset another domain account's password to hijack it (account takeover / "
             "lockout persistence).",
        technique="T1098", tactic="Persistence", category="Persistence",
        stage="Persistence", src=WS, dst=DC,
        privs="Reset Password extended right on the target user",
        prereqs=["User Account Management auditing (4724)"],
        tools=["net user <u> <pw> /domain", "Set-ADAccountPassword"],
        channels=["Security"], event_ids=["4724", "4738"], sysmon_ids=[],
        protocols=["SAMR", "LDAP"],
        wazuh_telemetry=["4724 password reset attempt where initiator != target and "
                         "initiator not a help-desk allowlist member"],
        fp="Help-desk resets are routine; key on initiator not in the reset-allowlist "
           "and target = privileged account.",
        support="assisted", prereq="ready", risk="medium",
        sim="Reset a throwaway lab account's password from WIN11; capture 4724; restore.",
        cleanup="Restore or rotate the affected account password.",
        rollback="Reset the account back to its known credential.",
        tcs=["account_management", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1484.001-MALICIOUS-GPO", name="Malicious GPO creation / modification",
        desc="Create or edit a GPO (e.g. scheduled task / restricted-groups / logon "
             "script) to push code or privilege to linked machines.",
        technique="T1484.001", tactic="Privilege Escalation", category="Privilege Escalation",
        stage="Privilege Escalation", src=WS, dst=DC,
        privs="Edit/link rights on a GPO or an OU",
        prereqs=["GPO edit/link rights", "DS Changes auditing (5136/5137) + SYSVOL Sysmon 11"],
        tools=["Group Policy Management", "New-GPO / Set-GPPrefRegistryValue", "SharpGPOAbuse"],
        channels=["Security", "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["5136", "5137", "5141"], sysmon_ids=["11"],
        protocols=["LDAP", "SMB"],
        wazuh_telemetry=["5137 groupPolicyContainer created / 5136 gPCMachineExtensionNames "
                         "modify", "Sysmon 11 writes under SYSVOL\\Policies"],
        fp="GPO edits by GPO admins are normal; key on non-GPO-admin initiator and "
           "high-risk extensions (scheduled tasks, scripts, restricted groups).",
        support="assisted", prereq="ready", risk="high",
        sim="Create a benign lab GPO, add an immediate scheduled task, capture 5137/5136/"
            "Sysmon-11, then unlink+delete.",
        cleanup="Unlink and delete the lab GPO; remove SYSVOL artifacts.",
        rollback="Delete created GPO; restore modified GPO from backup.",
        tcs=["ds_changes_audit", "sysmon_operational", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1047-REMOTE-WMI", name="Remote WMI execution",
        desc="Execute commands on a remote domain host via WMI (Win32_Process.Create) "
             "for lateral movement.",
        technique="T1047", tactic="Lateral Movement", category="Lateral Movement",
        stage="Lateral Movement", src=WS, dst=DC,
        privs="Local admin on the target",
        prereqs=["Local admin on target", "Sysmon + process-creation auditing on target"],
        tools=["wmic /node", "Invoke-WmiMethod", "impacket wmiexec"],
        channels=["Security", "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["4624", "4688"], sysmon_ids=["1", "3"],
        protocols=["DCOM/RPC", "TCP/135", "TCP/445"],
        wazuh_telemetry=["4624 type 3 to target", "Sysmon 1 child of WmiPrvSE.exe",
                         "4688 process with WmiPrvSE parent"],
        fp="WMI is used by legit management (SCCM); key on WmiPrvSE spawning shells "
           "(cmd/powershell) and unusual source host.",
        support="assisted", prereq="ready", risk="medium",
        sim="wmic /node:DC01 process call create 'whoami' from WIN11; capture Sysmon-1/4688.",
        cleanup="None (command only). Remove any marker file.",
        rollback="None.",
        tcs=["process_creation_cmdline", "sysmon_operational", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1021.006-REMOTE-WINRM", name="Remote WinRM execution",
        desc="Execute commands on a remote host over WinRM/PSRemoting (5985/5986).",
        technique="T1021.006", tactic="Lateral Movement", category="Lateral Movement",
        stage="Lateral Movement", src=WS, dst=DC,
        privs="Remote Management Users / local admin on target",
        prereqs=["WinRM enabled on target", "WinRM Operational + process auditing"],
        tools=["Enter-PSSession / Invoke-Command", "evil-winrm"],
        channels=["Security", "Microsoft-Windows-WinRM/Operational",
                  "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["4624", "4688"], sysmon_ids=["1"],
        protocols=["WinRM/HTTP", "TCP/5985", "TCP/5986"],
        wazuh_telemetry=["4624 type 3 to target", "Sysmon 1 wsmprovhost.exe spawning shells",
                         "WinRM Operational 91/168/169"],
        fp="WinRM is legit admin transport; key on wsmprovhost spawning cmd/powershell "
           "and unexpected source.",
        support="assisted", prereq="partially_ready", risk="medium",
        sim="Invoke-Command -ComputerName DC01 { whoami } from WIN11; capture Sysmon-1/4624.",
        cleanup="None.",
        rollback="None.",
        tcs=["process_creation_cmdline", "sysmon_operational", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1053.005-SCHTASK", name="Scheduled task creation on a domain system",
        desc="Create a scheduled task on a domain host (often remotely) for execution "
             "or persistence.",
        technique="T1053.005", tactic="Persistence", category="Persistence",
        stage="Persistence", src=WS, dst=DC,
        privs="Local admin on the target (for remote/system tasks)",
        prereqs=["Object Access / task auditing", "Sysmon on target"],
        tools=["schtasks /create /s", "Register-ScheduledTask"],
        channels=["Security", "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["4698", "4688"], sysmon_ids=["1"],
        protocols=["RPC", "TCP/445"],
        wazuh_telemetry=["4698 scheduled task created", "Sysmon 1 schtasks.exe with /create"],
        fp="Software installs create tasks legitimately; key on remote creation, "
           "suspicious actions (powershell -enc), and non-admin initiators.",
        support="assisted", prereq="ready", risk="medium",
        sim="schtasks /create /s DC01 /tn labtask /tr 'cmd /c whoami' /sc once ...; "
            "capture 4698; then /delete.",
        cleanup="schtasks /delete /s DC01 /tn labtask /f.",
        rollback="Delete the created task.",
        tcs=["object_access_audit", "process_creation_cmdline", "sysmon_operational", "wazuh_archives"],
    ),
    dict(
        key="AD-T1543.003-MAL-SERVICE", name="Malicious service creation on a domain system",
        desc="Install a new Windows service on a domain host (often remotely) to run "
             "code as SYSTEM / persist.",
        technique="T1543.003", tactic="Persistence", category="Persistence",
        stage="Persistence", src=WS, dst=DC,
        privs="Local admin on the target",
        prereqs=["System log collection", "Security 4697 auditing", "Sysmon on target"],
        tools=["sc create", "New-Service", "impacket services"],
        channels=["System", "Security", "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["7045", "4697"], sysmon_ids=["1"],
        protocols=["SCM/RPC", "TCP/445"],
        wazuh_telemetry=["7045 service installed (System)", "4697 service installed "
                         "(Security)", "Sysmon 1 sc.exe / services.exe child"],
        fp="Legit software installs services; key on unsigned binaries, temp/odd "
           "paths, cmd/powershell service binaries, remote creation.",
        support="assisted", prereq="ready", risk="medium",
        sim="sc \\\\DC01 create labsvc binPath= 'cmd /c whoami'; capture 7045/4697; delete.",
        cleanup="sc \\\\DC01 delete labsvc.",
        rollback="Delete the created service.",
        tcs=["system_log", "process_creation_cmdline", "sysmon_operational", "wazuh_archives"],
    ),
    dict(
        key="AD-T1556-SHADOW-CREDS", name="Shadow Credentials abuse",
        desc="Write msDS-KeyCredentialLink on a target to add attacker-controlled key "
             "material, enabling PKINIT auth as that principal.",
        technique="T1556", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="GenericWrite/WriteProperty (msDS-KeyCredentialLink) on the target",
        prereqs=["Write access to target's msDS-KeyCredentialLink",
                 "DS Changes auditing (5136)",
                 "PKINIT/AD CS for full auth (may be blocked in this lab)"],
        tools=["Whisker", "pyWhisker", "Rubeus asktgt /certificate"],
        channels=["Security"], event_ids=["5136"], sysmon_ids=[],
        protocols=["LDAP", "Kerberos/PKINIT"],
        wazuh_telemetry=["5136 modify of msDS-KeyCredentialLink"],
        fp="KeyCredentialLink writes are rare and privileged; low FP when keyed on the "
           "specific attribute. Note: full PKINIT step needs AD CS (not in this lab).",
        support="assisted", prereq="partially_ready", risk="high",
        sim="Add a key to a lab object's msDS-KeyCredentialLink; capture 5136; then remove. "
            "PKINIT auth step is blocked without AD CS.",
        cleanup="Clear the added msDS-KeyCredentialLink value.",
        rollback="Restore msDS-KeyCredentialLink to empty.",
        tcs=["ds_changes_audit", "security_log", "wazuh_archives"],
    ),
    # ---------- honestly BLOCKED / MANUAL / SAFE-EMULATION ----------
    dict(
        key="AD-T1649-ADCS-ESC1", name="AD CS ESC1 template abuse",
        desc="Abuse a misconfigured certificate template (ENROLLEE_SUPPLIES_SUBJECT + "
             "client-auth EKU) to enroll a cert as any user.",
        technique="T1649", tactic="Privilege Escalation", category="Privilege Escalation",
        stage="Privilege Escalation", src=WS, dst=DC,
        privs="Enrollment rights on a vulnerable template",
        prereqs=["AD CS Enterprise CA + vulnerable template (NOT present in this lab)"],
        tools=["Certify", "certipy"],
        channels=["Security"], event_ids=["4886", "4887"], sysmon_ids=[],
        protocols=["RPC", "HTTP"],
        wazuh_telemetry=["CertificateServices 4886/4887 with SAN != requester"],
        fp="Requires AD CS event source; not collectable without the role.",
        support="manual_only", prereq="blocked_by_prerequisite", risk="high",
        sim="BLOCKED: no AD CS role in the lab. Deploy an Enterprise CA to test.",
        cleanup="Revoke any issued certificate.",
        rollback="Fix template ACL/flags; revoke certs.",
        tcs=["cert_services_log", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1649-ADCS-ESC8", name="AD CS ESC8 NTLM relay to web enrollment",
        desc="Relay coerced machine NTLM auth to the AD CS web enrollment endpoint to "
             "obtain a certificate for the victim machine.",
        technique="T1649", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="Network position + coercion primitive",
        prereqs=["AD CS Web Enrollment (HTTP) + coercion (NOT present in this lab)"],
        tools=["certipy relay", "ntlmrelayx", "PetitPotam"],
        channels=["Security"], event_ids=["4886", "4624"], sysmon_ids=["3"],
        protocols=["HTTP", "SMB", "NTLM"],
        wazuh_telemetry=["Machine-account cert enrollment via HTTP after coerced auth"],
        fp="Requires AD CS web endpoint + relay infra; not testable here.",
        support="manual_only", prereq="blocked_by_prerequisite", risk="high",
        sim="BLOCKED: needs AD CS web enrollment + NTLM relay + coercion.",
        cleanup="Revoke issued certs; disable HTTP enrollment.",
        rollback="Revoke certs; enforce EPA/require-signing.",
        tcs=["cert_services_log", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1557.001-NTLM-RELAY", name="NTLM relay to LDAP / SMB",
        desc="Coerce a victim into authenticating, then relay that NTLM auth to LDAP/SMB "
             "to act as the victim (e.g. set RBCD).",
        technique="T1557.001", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="Network position + coercion primitive",
        prereqs=["Coercion primitive + a target without signing/EPA",
                 "Relay host (impacket) - manual setup"],
        tools=["ntlmrelayx", "PetitPotam", "Coercer"],
        channels=["Security"], event_ids=["4624", "4662", "5136"], sysmon_ids=["3"],
        protocols=["NTLM", "SMB", "LDAP"],
        wazuh_telemetry=["4624 NTLM from relay host", "downstream 5136 (e.g. RBCD write)"],
        fp="Relay is inferred from correlation (coerced auth -> privileged write from a "
           "relay host); hard from single events.",
        support="manual_only", prereq="partially_ready", risk="high",
        sim="MANUAL: stand up ntlmrelayx on a Linux host, coerce DC01, relay to LDAP. "
            "Requires manual relay infra.",
        cleanup="Revert any relayed change (e.g. clear RBCD).",
        rollback="Undo downstream writes; enable signing/EPA.",
        tcs=["ds_changes_audit", "security_log", "sysmon_operational", "wazuh_archives"],
    ),
    dict(
        key="AD-T1207-DCSHADOW", name="DCShadow rogue replication",
        desc="Register a rogue domain controller to push malicious directory changes via "
             "replication, bypassing normal change auditing.",
        technique="T1207", tactic="Defense Evasion", category="Defense Evasion",
        stage="Defense Evasion", src=WS, dst=DC,
        privs="Domain Admin (to register the temporary DC)",
        prereqs=["DA rights", "Second host to register as rogue DC",
                 "SNAPSHOT DC01 - high blast radius"],
        tools=["mimikatz lsadump::dcshadow"],
        channels=["Security", "Directory Service"], event_ids=["4662", "5137"], sysmon_ids=[],
        protocols=["DRSUAPI", "RPC"],
        wazuh_telemetry=["Unexpected nTDSDSA/server object creation (5137)",
                         "replication from a non-DC host"],
        fp="Very rare; signal is a new DSA/server object + replication from a "
           "non-DC. Requires DS-object baseline.",
        support="manual_only", prereq="partially_ready", risk="critical",
        sim="MANUAL ONLY: single-DC lab makes DCShadow high-risk; snapshot first, "
            "push one benign attribute change, then revert.",
        cleanup="Remove the rogue DSA/server objects; revert the pushed change.",
        rollback="Restore DC01 from snapshot if replication metadata is disturbed.",
        tcs=["ds_changes_audit", "ds_access_audit", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1555.006-LAPS-ACCESS", name="LAPS password access / discovery",
        desc="Read ms-Mcs-AdmPwd (legacy) / msLAPS-Password to recover managed local "
             "admin passwords from AD.",
        technique="T1555.006", tactic="Credential Access", category="Credential Access",
        stage="Credential Access", src=WS, dst=DC,
        privs="Read rights on the LAPS password attribute",
        prereqs=["LAPS deployed + schema extended (NOT deployed in this lab)"],
        tools=["Get-LAPSADPassword", "pyLAPS", "ldapsearch ms-Mcs-AdmPwd"],
        channels=["Security", "Directory Service"], event_ids=["4662"], sysmon_ids=[],
        protocols=["LDAP"],
        wazuh_telemetry=["4662 read of the LAPS password attribute by a non-admin"],
        fp="Needs LAPS schema + attribute auditing; not collectable without LAPS.",
        support="assisted", prereq="blocked_by_prerequisite", risk="medium",
        sim="BLOCKED: LAPS not deployed. Deploy LAPS + attribute auditing to test.",
        cleanup="Rotate any recovered local admin password.",
        rollback="Force LAPS password rotation.",
        tcs=["ds_access_audit", "object_access_audit", "wazuh_archives"],
    ),
    dict(
        key="AD-T1556.001-SKELETON-KEY", name="Skeleton Key (safe emulation)",
        desc="Patch LSASS on a DC so a master password authenticates as any user "
             "(in-memory, non-persistent).",
        technique="T1556.001", tactic="Credential Access", category="Defense Evasion",
        stage="Credential Access", src=DC, dst=DC,
        privs="Domain Admin / SYSTEM on the DC",
        prereqs=["Do NOT run the real patch on a shared DC", "Sysmon 10 LSASS access"],
        tools=["mimikatz misc::skeleton (EMULATE ONLY)"],
        channels=["Security", "Microsoft-Windows-Sysmon/Operational"],
        event_ids=["4673", "4611"], sysmon_ids=["10"],
        protocols=["Kerberos", "Local"],
        wazuh_telemetry=["Sysmon 10 access to lsass.exe by an unexpected process",
                         "RC4 downgrade on subsequent auth"],
        fp="Real detection relies on LSASS-access + auth-crypto anomalies; emulate the "
           "LSASS access rather than patching the DC.",
        support="safe_emulation_only", prereq="partially_ready", risk="critical",
        sim="SAFE EMULATION: generate a benign lsass access event (Sysmon 10) to test the "
            "detection path; do NOT run the real skeleton patch.",
        cleanup="Reboot DC to clear any in-memory patch (if ever run).",
        rollback="Reboot DC01; snapshot first.",
        tcs=["sysmon_operational", "security_log", "wazuh_archives"],
    ),
    dict(
        key="AD-T1484-UNCONSTRAINED-DELEG", name="Unconstrained delegation abuse",
        desc="Abuse a host trusted for unconstrained delegation to capture forwarded "
             "TGTs (often via coercion) and impersonate.",
        technique="T1484", tactic="Privilege Escalation", category="Privilege Escalation",
        stage="Privilege Escalation", src=WS, dst=DC,
        privs="Control of an unconstrained-delegation host + coercion",
        prereqs=["A host with TRUSTED_FOR_DELEGATION", "Coercion primitive (manual)",
                 "DS Changes auditing (5136) for the flag change"],
        tools=["Rubeus monitor", "PetitPotam", "PowerView"],
        channels=["Security"], event_ids=["5136", "4769", "4624"], sysmon_ids=[],
        protocols=["Kerberos", "RPC"],
        wazuh_telemetry=["5136 userAccountControl TRUSTED_FOR_DELEGATION set",
                         "captured TGTs (4769) on the delegation host"],
        fp="The attribute change (5136 UAC delegation bit) is loggable and rare; the "
           "TGT-capture step needs coercion and is manual.",
        support="assisted", prereq="partially_ready", risk="high",
        sim="Set TRUSTED_FOR_DELEGATION on a lab computer; capture 5136; then clear it. "
            "TGT-capture step is manual (needs coercion).",
        cleanup="Clear the TRUSTED_FOR_DELEGATION flag.",
        rollback="Reset userAccountControl delegation bits.",
        tcs=["ds_changes_audit", "kerberos_audit", "security_log", "wazuh_archives"],
    ),
]


def _j(x) -> str:
    return json.dumps(x, ensure_ascii=False)


def seed() -> int:
    conn = get_connection()
    try:
        cols = {r[0] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'ad_attack_tests'"
        )}
        if "attack_key" not in cols:
            print("ERROR: run migrate_004_ad_catalog.py first (missing columns).",
                  file=sys.stderr)
            return 2

        inserted = updated = 0
        for a in ATTACKS:
            exists = conn.execute(
                "SELECT 1 FROM ad_attack_tests WHERE test_id=%s", (a["key"],)
            ).fetchone()
            params = (
                a["key"], a["name"], a["technique"], a["src"], a["dst"],
                _j(a["channels"]), _j(a["event_ids"]), _j({}),
                a["sim"], a["cleanup"], a["risk"],
                a["key"], a["name"], a["desc"], a["category"], a["tactic"], a["stage"],
                a["privs"], _j(a["prereqs"]), _j(a["tools"]), _j(a["sysmon_ids"]),
                _j(a["protocols"]), _j(a["wazuh_telemetry"]), _j([]), _j([]),
                a["fp"], a["support"], a["prereq"], a["rollback"], "defined",
                _j(a["tcs"]), SEED_VERSION,
            )
            conn.execute(
                """
                INSERT INTO ad_attack_tests (
                    test_id, behavior_name, technique_id, execution_host, target_host,
                    expected_channels_json, expected_event_ids_json, expected_fields_json,
                    simulation_command, cleanup_command, risk_tier,
                    attack_key, display_name, description, attack_category, mitre_tactic,
                    attack_stage, required_privileges, prerequisites_json, required_tools_json,
                    expected_sysmon_ids_json, expected_protocols_json,
                    required_wazuh_telemetry_json, expected_wazuh_rules_json,
                    expected_sigma_rules_json, false_positive_notes, support_mode,
                    prerequisite_status, rollback_requirements, implementation_status,
                    telemetry_components_json, seed_version, enabled
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1)
                ON CONFLICT(test_id) DO UPDATE SET
                    behavior_name=excluded.behavior_name,
                    technique_id=excluded.technique_id,
                    execution_host=excluded.execution_host,
                    target_host=excluded.target_host,
                    expected_channels_json=excluded.expected_channels_json,
                    expected_event_ids_json=excluded.expected_event_ids_json,
                    simulation_command=excluded.simulation_command,
                    cleanup_command=excluded.cleanup_command,
                    risk_tier=excluded.risk_tier,
                    attack_key=excluded.attack_key,
                    display_name=excluded.display_name,
                    description=excluded.description,
                    attack_category=excluded.attack_category,
                    mitre_tactic=excluded.mitre_tactic,
                    attack_stage=excluded.attack_stage,
                    required_privileges=excluded.required_privileges,
                    prerequisites_json=excluded.prerequisites_json,
                    required_tools_json=excluded.required_tools_json,
                    expected_sysmon_ids_json=excluded.expected_sysmon_ids_json,
                    expected_protocols_json=excluded.expected_protocols_json,
                    required_wazuh_telemetry_json=excluded.required_wazuh_telemetry_json,
                    false_positive_notes=excluded.false_positive_notes,
                    support_mode=excluded.support_mode,
                    prerequisite_status=excluded.prerequisite_status,
                    rollback_requirements=excluded.rollback_requirements,
                    implementation_status=excluded.implementation_status,
                    telemetry_components_json=excluded.telemetry_components_json,
                    seed_version=excluded.seed_version
                """,
                params,
            )
            if exists:
                updated += 1
            else:
                inserted += 1

        conn.commit()

        total = conn.execute("SELECT COUNT(*) FROM ad_attack_tests").fetchone()[0]
        new_total = conn.execute(
            "SELECT COUNT(*) FROM ad_attack_tests WHERE seed_version=%s", (SEED_VERSION,)
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM ad_attack_tests WHERE prerequisite_status="
            "'blocked_by_prerequisite'"
        ).fetchone()[0]
        print(f"[seed_ad_catalog] seed_version={SEED_VERSION}")
        print(f"  inserted new attacks : {inserted}")
        print(f"  refreshed existing   : {updated}")
        print(f"  attacks in this seed : {new_total}")
        print(f"    of which blocked   : {blocked}")
        print(f"  ad_attack_tests TOTAL: {total} (6 original + {new_total} new)")
        print("  OK")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=None, help="unused — connection comes from .env (DB_* vars)")
    args = p.parse_args()
    raise SystemExit(seed())
