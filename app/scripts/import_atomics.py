"""
Import Atomic Red Team test definitions and turn each into one OR MORE
Sysmon-style sample events linked to detection rules.

Each atomic test produces:
  • Always:    EventID 1  (process_creation)  — with full Sysmon field set
  • Sometimes: EventID 11 (file_create)       — if the command writes a file
  • Sometimes: EventID 3  (network_connect)   — if the command does HTTP/IP IO
  • Sometimes: EventID 22 (dns_query)         — companion to network_connect
  • Sometimes: EventID 13 (registry_set)      — if the command writes registry

This means a single atomic can generate 1–5 sample logs, each tested
independently against the rules whose selection keywords overlap.

Run once after cloning the atomic-red-team repo:

    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/redcanaryco/atomic-red-team.git /tmp/art
    git -C /tmp/art sparse-checkout set atomics
    python -m app.scripts.import_atomics --atomics /tmp/art/atomics
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

import yaml

if __package__ in (None, ""):
    HERE = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(HERE))

from app.database import get_connection


# ── Executor → spawn binary lookup ──────────────────────────────────────────

WINDOWS_EXECUTORS = {
    "powershell":     ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    "command_prompt": ("cmd.exe",        "C:\\Windows\\System32\\cmd.exe"),
}
LINUX_EXECUTORS = {"sh": ("sh", "/bin/sh"), "bash": ("bash", "/bin/bash")}
MACOS_EXECUTORS = {"sh": ("sh", "/bin/sh"), "bash": ("bash", "/bin/bash")}


# ── PE metadata for common Windows binaries ─────────────────────────────────
# Real Sysmon reads these from the file's version info. We mirror the
# canonical capitalisation + descriptions Sysmon would emit so rules that
# select on OriginalFileName/Company/Description match correctly.

_MS = "Microsoft Corporation"
_MS_OS = "Microsoft\u00ae Windows\u00ae Operating System"

PE_INFO = {
    "powershell.exe": {"OriginalFileName": "PowerShell.EXE",  "Company": _MS, "Description": "Windows PowerShell",            "Product": _MS_OS},
    "pwsh.exe":       {"OriginalFileName": "pwsh.dll",        "Company": _MS, "Description": "PowerShell 7",                  "Product": "PowerShell"},
    "cmd.exe":        {"OriginalFileName": "Cmd.Exe",         "Company": _MS, "Description": "Windows Command Processor",     "Product": _MS_OS},
    "rundll32.exe":   {"OriginalFileName": "RUNDLL32.EXE",    "Company": _MS, "Description": "Windows host process (Rundll32)","Product": _MS_OS},
    "regsvr32.exe":   {"OriginalFileName": "REGSVR32.EXE",    "Company": _MS, "Description": "Microsoft(C) Register Server",  "Product": _MS_OS},
    "reg.exe":        {"OriginalFileName": "reg.exe",         "Company": _MS, "Description": "Registry Console Tool",         "Product": _MS_OS},
    "schtasks.exe":   {"OriginalFileName": "schtasks.exe",    "Company": _MS, "Description": "Task Scheduler Configuration Tool", "Product": _MS_OS},
    "wmic.exe":       {"OriginalFileName": "wmic.exe",        "Company": _MS, "Description": "WMI Commandline Utility",       "Product": _MS_OS},
    "net.exe":        {"OriginalFileName": "net.exe",         "Company": _MS, "Description": "Net Command",                   "Product": _MS_OS},
    "net1.exe":       {"OriginalFileName": "net1.exe",        "Company": _MS, "Description": "Net Command",                   "Product": _MS_OS},
    "bitsadmin.exe":  {"OriginalFileName": "bitsadmin.exe",   "Company": _MS, "Description": "BITS administration utility",   "Product": _MS_OS},
    "certutil.exe":   {"OriginalFileName": "CertUtil.exe.mui","Company": _MS, "Description": "CertUtil.exe",                  "Product": _MS_OS},
    "mshta.exe":      {"OriginalFileName": "mshta.exe",       "Company": _MS, "Description": "Microsoft (R) HTML Application host", "Product": _MS_OS},
    "wscript.exe":    {"OriginalFileName": "wscript.exe",     "Company": _MS, "Description": "Microsoft (R) Windows Based Script Host", "Product": _MS_OS},
    "cscript.exe":    {"OriginalFileName": "cscript.exe",     "Company": _MS, "Description": "Microsoft (R) Console Based Script Host", "Product": _MS_OS},
    "ntdsutil.exe":   {"OriginalFileName": "ntdsutil.exe",    "Company": _MS, "Description": "NT5DS",                         "Product": _MS_OS},
    "vssadmin.exe":   {"OriginalFileName": "VSSADMIN.EXE",    "Company": _MS, "Description": "Command Line Interface for Microsoft\u00ae Volume Shadow Copy Service", "Product": _MS_OS},
    "wevtutil.exe":   {"OriginalFileName": "wevtutil.exe",    "Company": _MS, "Description": "Eventing Command Line Utility", "Product": _MS_OS},
    "tasklist.exe":   {"OriginalFileName": "tasklist.exe",    "Company": _MS, "Description": "Lists the current running tasks","Product": _MS_OS},
    "taskkill.exe":   {"OriginalFileName": "taskkill.exe",    "Company": _MS, "Description": "Terminates Processes",          "Product": _MS_OS},
    "whoami.exe":     {"OriginalFileName": "whoami.exe",      "Company": _MS, "Description": "whoami - displays logged on user information", "Product": _MS_OS},
    "netsh.exe":      {"OriginalFileName": "netsh.exe",       "Company": _MS, "Description": "Network Command Shell",         "Product": _MS_OS},
    "sc.exe":         {"OriginalFileName": "sc.exe",          "Company": _MS, "Description": "Service Control Manager Configuration Tool", "Product": _MS_OS},
}

# Atomic-dropped third-party tools — known PE info we can synthesize.
EXTERNAL_PE_INFO = {
    "procdump.exe":         {"OriginalFileName": "procdump", "Company": "Sysinternals - www.sysinternals.com", "Description": "Sysinternals process dump utility", "Product": "ProcDump"},
    "procdump64.exe":       {"OriginalFileName": "procdump", "Company": "Sysinternals - www.sysinternals.com", "Description": "Sysinternals process dump utility", "Product": "ProcDump"},
    "nanodump.exe":         {"OriginalFileName": "nanodump.x64.exe", "Company": "Helpsystems", "Description": "NanoDump", "Product": "NanoDump"},
    "mimikatz.exe":         {"OriginalFileName": "mimikatz.exe", "Company": "Benjamin DELPY (gentilkiwi)", "Description": "mimikatz for Windows", "Product": "mimikatz"},
    "psexec.exe":           {"OriginalFileName": "psexec.c",  "Company": "Sysinternals - www.sysinternals.com", "Description": "Execute processes remotely", "Product": "Sysinternals PsExec"},
    "psexec64.exe":         {"OriginalFileName": "psexec.c",  "Company": "Sysinternals - www.sysinternals.com", "Description": "Execute processes remotely", "Product": "Sysinternals PsExec"},
    "psexesvc.exe":         {"OriginalFileName": "PSEXESVC",  "Company": "Sysinternals - www.sysinternals.com", "Description": "PsExec Service",              "Product": "Sysinternals PsExec"},
}


def _basename(path: str) -> str:
    """Cross-platform basename — handles both \\ and / separators."""
    return re.split(r"[\\/]", path)[-1]


def _pe_info_for(image: str) -> dict:
    base = _basename(image).lower()
    if base in PE_INFO:
        return PE_INFO[base]
    if base in EXTERNAL_PE_INFO:
        return EXTERNAL_PE_INFO[base]
    # Generic fallback for unknown binaries.
    return {"OriginalFileName": _basename(image), "Company": "", "Description": "", "Product": ""}


# ── Hashes (deterministic, look-real) ───────────────────────────────────────

def _fake_hashes(image: str) -> str:
    """
    Build a Sysmon-style Hashes field. Deterministic from the image path so
    repeated runs of the importer are stable.
    """
    seed = image.encode("utf-8")
    md5 = hashlib.md5(seed).hexdigest().upper()
    sha1 = hashlib.sha1(seed).hexdigest().upper()
    sha256 = hashlib.sha256(seed).hexdigest().upper()
    imphash = hashlib.md5(seed + b"imphash").hexdigest().upper()
    return f"MD5={md5},SHA1={sha1},SHA256={sha256},IMPHASH={imphash}"


def _process_guid(seed: str) -> str:
    """Stable GUID per (atomic, role) pair so events relate consistently."""
    h = hashlib.md5(seed.encode("utf-8")).hexdigest()
    return "{" + f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}".upper() + "}"


# ── Argument resolution ─────────────────────────────────────────────────────

BUILTIN_ATOMIC_PATHS = {
    "PathToAtomicsFolder": "C:\\AtomicRedTeam\\atomics",
    "PathToPayloadsFolder": "C:\\AtomicRedTeam\\ExternalPayloads",
}


def resolve_args(text: str, input_arguments: dict | None) -> str:
    """Substitute #{name} placeholders with declared defaults and built-ins."""
    if not text:
        return ""
    args = dict(BUILTIN_ATOMIC_PATHS)
    if input_arguments:
        for name, body in input_arguments.items():
            default = (body or {}).get("default")
            if default is not None:
                args[name] = str(default)

    def repl(match):
        return args.get(match.group(1), match.group(0))
    out = re.sub(r"#\{([A-Za-z0-9_]+)\}", repl, text)
    # Many atomics use bare "PathToAtomicsFolder\..\X" strings (no #{} braces)
    # baked into their commands. Normalise those too.
    out = out.replace("PathToAtomicsFolder\\..\\ExternalPayloads", "C:\\AtomicRedTeam\\ExternalPayloads")
    out = out.replace("PathToAtomicsFolder\\..\\atomics",         "C:\\AtomicRedTeam\\atomics")
    out = out.replace("PathToAtomicsFolder",                       "C:\\AtomicRedTeam\\atomics")
    out = out.replace("C:\\AtomicRedTeam\\atomics\\..\\ExternalPayloads", "C:\\AtomicRedTeam\\ExternalPayloads")
    return out


# ── Binary extraction ──────────────────────────────────────────────────────

_WIN_BIN_RE = re.compile(
    r'(?:"([A-Za-z]:\\[^"]+\.(?:exe|bat|cmd|ps1|vbs|js|wsf|msi|com|scr|pif|dll))")'
    r'|((?:[A-Za-z]:\\[^\s"]+\.(?:exe|bat|cmd|ps1|vbs|js|wsf|msi|com|scr|pif|dll))'
    r'|(?:[A-Za-z0-9_.\-]+\.(?:exe|bat|cmd|ps1|vbs|js|wsf|msi|com|scr|pif|dll)))',
    re.IGNORECASE,
)
_PS_LAUNCHER_RE = re.compile(
    r"(?:Start-Process|Invoke-Item|&\s*)\s+['\"]?([A-Za-z]:\\[^'\"\s]+\.exe|[\w.-]+\.exe)['\"]?",
    re.IGNORECASE,
)


def _windows_full_path(name: str) -> str:
    if "\\" in name:
        return name
    n = name.lower()
    system_apps = {
        "cmd.exe":         "C:\\Windows\\System32\\cmd.exe",
        "powershell.exe":  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pwsh.exe":        "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
        "rundll32.exe":    "C:\\Windows\\System32\\rundll32.exe",
        "regsvr32.exe":    "C:\\Windows\\System32\\regsvr32.exe",
        "reg.exe":         "C:\\Windows\\System32\\reg.exe",
        "schtasks.exe":    "C:\\Windows\\System32\\schtasks.exe",
        "wmic.exe":        "C:\\Windows\\System32\\wbem\\WMIC.exe",
        "net.exe":         "C:\\Windows\\System32\\net.exe",
        "net1.exe":        "C:\\Windows\\System32\\net1.exe",
        "bitsadmin.exe":   "C:\\Windows\\System32\\bitsadmin.exe",
        "certutil.exe":    "C:\\Windows\\System32\\certutil.exe",
        "mshta.exe":       "C:\\Windows\\System32\\mshta.exe",
        "wscript.exe":     "C:\\Windows\\System32\\wscript.exe",
        "cscript.exe":     "C:\\Windows\\System32\\cscript.exe",
        "ntdsutil.exe":    "C:\\Windows\\System32\\ntdsutil.exe",
        "vssadmin.exe":    "C:\\Windows\\System32\\vssadmin.exe",
        "wevtutil.exe":    "C:\\Windows\\System32\\wevtutil.exe",
        "tasklist.exe":    "C:\\Windows\\System32\\tasklist.exe",
        "taskkill.exe":    "C:\\Windows\\System32\\taskkill.exe",
        "whoami.exe":      "C:\\Windows\\System32\\whoami.exe",
        "netsh.exe":       "C:\\Windows\\System32\\netsh.exe",
        "sc.exe":          "C:\\Windows\\System32\\sc.exe",
    }
    if n in system_apps:
        return system_apps[n]
    return f"C:\\AtomicRedTeam\\ExternalPayloads\\{name}"


def _extract_windows_spawn(command: str) -> tuple[str, str]:
    m = _WIN_BIN_RE.search(command)
    if not m:
        return "", ""
    name = m.group(1) or m.group(2)
    return _windows_full_path(name), command


def _extract_linux_spawn(command: str) -> str:
    tokens = command.strip().split()
    if not tokens:
        return ""
    first = tokens[0]
    if first in ("sudo", "env", "exec") and len(tokens) > 1:
        first = tokens[1]
    if "/" in first:
        return first
    common = {
        "find":"/usr/bin/find", "ls":"/usr/bin/ls", "cat":"/usr/bin/cat",
        "curl":"/usr/bin/curl", "wget":"/usr/bin/wget", "python":"/usr/bin/python3",
        "python3":"/usr/bin/python3", "perl":"/usr/bin/perl", "nc":"/usr/bin/nc",
        "ncat":"/usr/bin/ncat", "bash":"/bin/bash", "sh":"/bin/sh",
        "chmod":"/usr/bin/chmod", "chown":"/usr/bin/chown", "setcap":"/usr/sbin/setcap",
        "useradd":"/usr/sbin/useradd", "crontab":"/usr/bin/crontab",
    }
    return common.get(first, f"/usr/bin/{first}")


# ── Detectors for secondary events ─────────────────────────────────────────
# These extract intent from the atomic command line. Best-effort regex —
# false positives are fine (an extra event is just one extra sample), false
# negatives are what we want to minimise.

_FILE_WRITE_RE = re.compile(
    r"(?:"
    r"-OutFile\s+['\"]?([^'\"\s|<>]+)"
    r"|Out-File\s+(?:-FilePath\s+)?['\"]?([^'\"\s|<>]+)"
    r"|Set-Content\s+(?:-Path\s+)?['\"]?([^'\"\s|<>]+)"
    r"|Add-Content\s+(?:-Path\s+)?['\"]?([^'\"\s|<>]+)"
    r"|New-Item\s+(?:-Path\s+)?['\"]?([^'\"\s|<>]+\.[A-Za-z0-9]{1,5})"
    r"|\s>>?\s+['\"]?([A-Za-z]:\\[^'\"\s<>|]+|/[^'\"\s<>|]+)"
    r"|/transfer\s+\w+\s+\S+\s+([A-Za-z]:\\[^'\"\s<>|]+)"
    r")",
    re.IGNORECASE,
)
_NETWORK_RE = re.compile(
    r"(?:"
    r"https?://([A-Za-z0-9.\-]+)(?::(\d+))?(?:/[^\s'\"]*)?"
    r"|(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?"
    r")",
    re.IGNORECASE,
)
_REGISTRY_RE = re.compile(
    r"(?:"
    r"(?:Set|New)-Item(?:Property)?\s+(?:-Path\s+)?['\"]?(HK(?:LM|CU|U|CR|CC|LM_64|LM_32|LM_LOCAL_MACHINE)?[:\\][^\s'\"]+)"
    r"|reg(?:\.exe)?\s+add\s+['\"]?(HK(?:LM|CU|U|CR|CC|LM_64|LM_32|LM_LOCAL_MACHINE)?\\[^\s'\"]+)(?:.*?/v\s+['\"]?([^'\"\s]+))?(?:.*?/d\s+['\"]?([^'\"]+)['\"]?)?"
    r")",
    re.IGNORECASE,
)


def _detect_file_writes(command: str, output_file_argument: str | None) -> list[str]:
    writes: list[str] = []
    if output_file_argument:
        writes.append(output_file_argument)
    for groups in _FILE_WRITE_RE.findall(command):
        for g in groups:
            if g and "/" not in g and "\\" not in g and ":" not in g and "." not in g:
                continue
            if g:
                writes.append(g.strip(""""' """))
    # Cleanup: keep distinct, drop obvious noise
    seen = set()
    out: list[str] = []
    for w in writes:
        if not w or w in seen:
            continue
        seen.add(w)
        out.append(w)
    return out[:5]


def _detect_network(command: str) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    seen = set()
    for groups in _NETWORK_RE.findall(command):
        host = groups[0] or groups[2]
        port_str = groups[1] or groups[3]
        if not host:
            continue
        # Skip obvious noise — local loopback, version strings like "4.0.30319"
        if host.startswith(("127.", "0.")):
            continue
        # Numeric segments only — likely a .NET version (e.g. 4.0.30319.0)
        if re.fullmatch(r"\d+(?:\.\d+){2,}", host) and not port_str:
            continue
        port = int(port_str) if port_str and port_str.isdigit() else (443 if command.lower().find("https") >= 0 else 80)
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        targets.append(key)
        if len(targets) >= 3:
            break
    return targets


# Processes attacker tools commonly open handles to — Sysmon EventID 10.
SENSITIVE_TARGET_PROCESSES = {
    "lsass":     "C:\\Windows\\System32\\lsass.exe",
    "winlogon":  "C:\\Windows\\System32\\winlogon.exe",
    "csrss":     "C:\\Windows\\System32\\csrss.exe",
    "smss":      "C:\\Windows\\System32\\smss.exe",
    "services":  "C:\\Windows\\System32\\services.exe",
    "lsm":       "C:\\Windows\\System32\\lsm.exe",
}


def _detect_process_access(command: str) -> list[str]:
    """Return list of TargetImage paths for sensitive processes mentioned."""
    cl = command.lower()
    hits: list[str] = []
    for kw, image in SENSITIVE_TARGET_PROCESSES.items():
        if kw in cl:
            hits.append(image)
    return hits


# Well-known DLLs that show up in atomic tests, mapped to their canonical path.
KNOWN_DLLS = {
    "comsvcs.dll":     "C:\\Windows\\System32\\comsvcs.dll",
    "scrobj.dll":      "C:\\Windows\\System32\\scrobj.dll",
    "shell32.dll":     "C:\\Windows\\System32\\shell32.dll",
    "amsi.dll":        "C:\\Windows\\System32\\amsi.dll",
    "vaultcli.dll":    "C:\\Windows\\System32\\vaultcli.dll",
    "kernel32.dll":    "C:\\Windows\\System32\\kernel32.dll",
    "ntdll.dll":       "C:\\Windows\\System32\\ntdll.dll",
    "wininet.dll":     "C:\\Windows\\System32\\wininet.dll",
    "winhttp.dll":     "C:\\Windows\\System32\\winhttp.dll",
    "psapi.dll":       "C:\\Windows\\System32\\psapi.dll",
    "samlib.dll":      "C:\\Windows\\System32\\samlib.dll",
    "secur32.dll":     "C:\\Windows\\System32\\secur32.dll",
    "advapi32.dll":    "C:\\Windows\\System32\\advapi32.dll",
    "dbghelp.dll":     "C:\\Windows\\System32\\dbghelp.dll",
    "dbgcore.dll":     "C:\\Windows\\System32\\dbgcore.dll",
}


def _detect_image_loads(command: str, spawn_image: str) -> list[str]:
    """Return list of loaded DLLs that this atomic likely triggers."""
    loads: list[str] = []
    cl = command.lower()
    # 1) Explicit DLL mentions in the command (e.g., 'rundll32 X.dll,...').
    for m in re.finditer(r"([A-Za-z][A-Za-z0-9_\-]*\.dll)", command, re.IGNORECASE):
        name = m.group(1).lower()
        loads.append(KNOWN_DLLS.get(name, f"C:\\AtomicRedTeam\\ExternalPayloads\\{name}"))
    # 2) Implicit: anything launched by rundll32/regsvr32 loads at least one DLL.
    spawn_base = _basename(spawn_image).lower()
    if spawn_base in ("rundll32.exe", "regsvr32.exe") and not loads:
        loads.append("C:\\Windows\\System32\\shell32.dll")
    # 3) Credential-dump command lines virtually always touch dbghelp + dbgcore.
    if any(kw in cl for kw in ("sekurlsa", "lsadump", "minidump", "comsvcs", "lsass")):
        loads.append(KNOWN_DLLS["dbghelp.dll"])
        loads.append(KNOWN_DLLS["dbgcore.dll"])
    # Dedupe, cap.
    seen = set()
    out: list[str] = []
    for x in loads:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out[:4]


# Realistic parent process per MITRE technique. Atomics test the *behaviour*
# but don't simulate the parent context — for example, a T1059.001 payload
# (PowerShell exec) is almost always launched by an Office process in the
# real world. Reflecting that lets rules that select on ParentImage match.
TECHNIQUE_PARENT = {
    # Macro / Office spawning shells
    "T1059.001":  "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "T1204.002":  "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "T1137":      "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "T1137.001":  "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    # Scheduled tasks
    "T1053":      "C:\\Windows\\System32\\svchost.exe",
    "T1053.005":  "C:\\Windows\\System32\\svchost.exe",
    # Services (T1543.003 etc.)
    "T1543":      "C:\\Windows\\System32\\services.exe",
    "T1543.003":  "C:\\Windows\\System32\\services.exe",
    # WMI persistence
    "T1546.003":  "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    "T1047":      "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    # PsExec lateral movement (T1021.002, T1570)
    "T1021.002":  "C:\\Windows\\PSEXESVC.exe",
}


def _detect_registry_writes(command: str) -> list[tuple[str, str, str]]:
    """Returns list of (registry_path, value_name, value_data)."""
    writes: list[tuple[str, str, str]] = []
    for groups in _REGISTRY_RE.findall(command):
        ps_path, reg_path, reg_value, reg_data = groups
        path = (ps_path or reg_path or "").strip(""""' """)
        if not path:
            continue
        # Normalise HKLM:\... → HKLM\...
        path = path.replace(":\\", "\\")
        value_name = (reg_value or "").strip(""""' """)
        value_data = (reg_data or "").strip(""""' """)
        writes.append((path, value_name, value_data))
        if len(writes) >= 5:
            break
    # PowerShell pattern: Set-ItemProperty -Path X -Name Y -Value Z
    for m in re.finditer(
        r"(?:Set|New)-ItemProperty\s+(?:-Path\s+)?['\"]?(HK[A-Z_]*[:\\][^\s'\"]+)['\"]?"
        r"(?:[^|;]*?-Name\s+['\"]?([^\s'\"]+))?(?:[^|;]*?-Value\s+['\"]?([^'\"]+?)['\"]?(?=\s+-|\s*$|\s*\||\s*;))?",
        command, re.IGNORECASE,
    ):
        path = m.group(1).replace(":\\", "\\").strip(""""' """)
        writes.append((path, (m.group(2) or "").strip(""""' """), (m.group(3) or "").strip(""""' """)))
    seen = set()
    out: list[tuple[str, str, str]] = []
    for w in writes:
        key = (w[0].lower(), w[1].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(w)
    return out[:5]


# ── Event builders ─────────────────────────────────────────────────────────

USER_DEFAULT = "CORP\\redteam"
LOGON_ID = "0x3E7"
LOGON_GUID = "{B5C2D8E7-AB42-66DE-0000-002030F2A9C8}"


def _make_process_creation(
    spawn_image: str, spawn_cmdline: str, parent_image: str,
    parent_cmdline: str, integrity: str, atomic_guid: str,
) -> dict:
    pid_seed = atomic_guid + ":proc"
    parent_seed = atomic_guid + ":parent"
    return {
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "RuleName": "-",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid":       _process_guid(pid_seed),
        "ProcessId":         4242,
        "Image":             spawn_image,
        "FileVersion":       "10.0.19041.1",
        "Description":       _pe_info_for(spawn_image)["Description"],
        "Product":           _pe_info_for(spawn_image)["Product"],
        "Company":           _pe_info_for(spawn_image)["Company"],
        "OriginalFileName":  _pe_info_for(spawn_image)["OriginalFileName"],
        "CommandLine":       spawn_cmdline,
        "CurrentDirectory":  "C:\\Users\\redteam\\",
        "User":              USER_DEFAULT,
        "LogonGuid":         LOGON_GUID,
        "LogonId":            LOGON_ID,
        "TerminalSessionId":  1,
        "IntegrityLevel":     integrity,
        "Hashes":             _fake_hashes(spawn_image),
        "ParentProcessGuid":  _process_guid(parent_seed),
        "ParentProcessId":    4200,
        "ParentImage":        parent_image,
        "ParentCommandLine":  parent_cmdline,
        "ParentUser":         USER_DEFAULT,
    }


def _make_file_create(spawn_image: str, target_filename: str, atomic_guid: str) -> dict:
    return {
        "EventID": 11,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "RuleName": "-",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid":     _process_guid(atomic_guid + ":proc"),
        "ProcessId":        4242,
        "Image":            spawn_image,
        "TargetFilename":   target_filename,
        "CreationUtcTime":  datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "User":             USER_DEFAULT,
    }


def _make_network_connection(spawn_image: str, host: str, port: int, atomic_guid: str) -> dict:
    return {
        "EventID": 3,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "RuleName": "-",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid":      _process_guid(atomic_guid + ":proc"),
        "ProcessId":         4242,
        "Image":             spawn_image,
        "User":              USER_DEFAULT,
        "Protocol":          "tcp",
        "Initiated":         "true",
        "SourceIsIpv6":      "false",
        "SourceIp":          "10.0.0.42",
        "SourceHostname":    "WORKSTATION01",
        "SourcePort":        49654,
        "DestinationIsIpv6": "false",
        "DestinationIp":     host if re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host) else "203.0.113.10",
        "DestinationHostname": host if not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host) else "",
        "DestinationPort":   port,
    }


def _make_dns_query(spawn_image: str, query: str, atomic_guid: str) -> dict:
    return {
        "EventID": 22,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "RuleName": "-",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid":  _process_guid(atomic_guid + ":proc"),
        "ProcessId":     4242,
        "Image":         spawn_image,
        "User":          USER_DEFAULT,
        "QueryName":     query,
        "QueryStatus":   0,
        "QueryResults":  "type:  5 cdn.example.com.;::ffff:203.0.113.10;",
    }


def _make_powershell_scriptblock(spawn_image: str, script_text: str, atomic_guid: str) -> dict:
    """EventID 4104 — PowerShell script-block logging."""
    return {
        "EventID": 4104,
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "Provider_Name": "Microsoft-Windows-PowerShell",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "ScriptBlockText": script_text,
        "ScriptBlockId":   _process_guid(atomic_guid + ":scriptblock"),
        "Path":            "",
        "MessageNumber":   1,
        "MessageTotal":    1,
        "Image":           spawn_image,
        "User":            USER_DEFAULT,
        "ProcessId":        4242,
    }


def _make_process_access(spawn_image: str, target_image: str, atomic_guid: str) -> dict:
    """EventID 10 — process opened a handle to another process."""
    return {
        "EventID": 10,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "SourceProcessGuid":  _process_guid(atomic_guid + ":proc"),
        "SourceProcessId":     4242,
        "SourceImage":         spawn_image,
        "TargetProcessGuid":   _process_guid(atomic_guid + ":" + target_image),
        "TargetProcessId":     600,
        "TargetImage":         target_image,
        "GrantedAccess":       "0x1FFFFF",  # PROCESS_ALL_ACCESS — classic credential-dump pattern
        "CallTrace":           ("C:\\Windows\\System32\\ntdll.dll+9d144|"
                                "C:\\Windows\\System32\\KERNELBASE.dll+30b73|"
                                "UNKNOWN(00007FF6A1B12345)"),
        "SourceUser":          USER_DEFAULT,
        "TargetUser":          "NT AUTHORITY\\SYSTEM",
    }


def _make_image_load(image: str, image_loaded: str, atomic_guid: str) -> dict:
    """EventID 7 — DLL/module loaded into a running process."""
    info = _pe_info_for(image_loaded)
    return {
        "EventID": 7,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "ProcessGuid":      _process_guid(atomic_guid + ":proc"),
        "ProcessId":         4242,
        "Image":             image,
        "ImageLoaded":       image_loaded,
        "FileVersion":       "10.0.19041.1",
        "Description":       info["Description"],
        "Product":           info["Product"],
        "Company":           info["Company"],
        "OriginalFileName":  info["OriginalFileName"],
        "Hashes":            _fake_hashes(image_loaded),
        "Signed":            "false",
        "Signature":         "",
        "SignatureStatus":   "Unavailable",
        "User":              USER_DEFAULT,
    }


def _make_registry_set(spawn_image: str, target_object: str, details: str, atomic_guid: str) -> dict:
    return {
        "EventID": 13,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "RuleName": "-",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "EventType":     "SetValue",
        "ProcessGuid":   _process_guid(atomic_guid + ":proc"),
        "ProcessId":      4242,
        "Image":          spawn_image,
        "User":           USER_DEFAULT,
        "TargetObject":   target_object,
        "Details":        details or "(empty)",
    }


def _make_linux_process_creation(spawn_image: str, command: str, parent_image: str) -> dict:
    return {
        "EventID": 1,
        "Provider_Name": "Linux-Sysmon",
        "UtcTime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.000"),
        "Image":              spawn_image,
        "CommandLine":        command,
        "CurrentDirectory":   "/home/redteam",
        "User":               "redteam",
        "LogonId":             1000,
        "TerminalSessionId":   3,
        "ProcessId":           4242,
        "ParentImage":         parent_image,
        "ParentCommandLine":   f"{parent_image} -c \"{command}\"",
        "Hashes":              _fake_hashes(spawn_image),
    }


# ── Top-level: produce ALL events for one atomic test ───────────────────────

def make_event_samples(
    executor_name: str, command: str, platform: str,
    test_guid: str, input_arguments: dict | None,
    elevation_required: bool, technique_id: str = "",
) -> list[tuple[str, dict]]:
    """Return list of (subtype, event_dict) for one atomic test."""
    command = command.strip().replace("\n", " ")
    command = re.sub(r"\s+", " ", command)
    if not command:
        return []

    atomic_guid = test_guid or hashlib.md5(command.encode()).hexdigest()
    output_file = (input_arguments or {}).get("output_file", {}).get("default") if input_arguments else None
    integrity = "High" if elevation_required else "Medium"

    events: list[tuple[str, dict]] = []

    if platform == "windows":
        spec = WINDOWS_EXECUTORS.get(executor_name)
        if not spec:
            return []
        _, parent_image = spec

        # Realistic parent based on technique (Office for macro execution etc.)
        realistic_parent = TECHNIQUE_PARENT.get(technique_id) or TECHNIQUE_PARENT.get(
            (technique_id.split(".")[0] if technique_id else ""), None
        )

        if executor_name == "powershell":
            m = _PS_LAUNCHER_RE.search(command)
            if m:
                spawn_image = _windows_full_path(m.group(1))
                spawn_cmdline = command
            else:
                spawn_image = parent_image
                spawn_cmdline = f'"{parent_image}" -NoProfile -ExecutionPolicy Bypass -Command "{command}"'
            # If the technique implies an Office/scheduled-task/service parent,
            # use that. Otherwise default to explorer.exe.
            if realistic_parent:
                parent_img = realistic_parent
                parent_cmd = f'"{realistic_parent}"'
            else:
                parent_img = "C:\\Windows\\explorer.exe"
                parent_cmd = "C:\\Windows\\Explorer.EXE"
        else:
            spawn_image, spawn_cmdline = _extract_windows_spawn(command)
            if not spawn_image:
                spawn_image = parent_image
                spawn_cmdline = f'"{parent_image}" /c {command}'
            if realistic_parent:
                parent_img = realistic_parent
                parent_cmd = f'"{realistic_parent}"'
            else:
                parent_img = parent_image
                parent_cmd = f'"{parent_image}" /c {command}'

        events.append((
            "process_creation",
            _make_process_creation(spawn_image, spawn_cmdline, parent_img, parent_cmd, integrity, atomic_guid),
        ))

        # EventID 4104 — script-block logging, for every PowerShell atomic.
        if executor_name == "powershell":
            events.append((
                "powershell_scriptblock",
                _make_powershell_scriptblock(spawn_image, command, atomic_guid),
            ))

        # EventID 10 — handle to sensitive process (lsass etc.)
        for target_image in _detect_process_access(command):
            events.append((
                "process_access",
                _make_process_access(spawn_image, target_image, atomic_guid),
            ))

        # EventID 7 — DLL loads (rundll32/regsvr32/credential-dump atomics)
        for dll_path in _detect_image_loads(command, spawn_image):
            events.append((
                "image_load",
                _make_image_load(spawn_image, dll_path, atomic_guid),
            ))

        # EventID 11 — files written
        for tf in _detect_file_writes(command, output_file):
            if not tf or len(tf) < 4:
                continue
            events.append(("file_create", _make_file_create(spawn_image, tf, atomic_guid)))

        # EventID 3 + 22 — network IO + DNS
        for host, port in _detect_network(command):
            events.append(("network_connection", _make_network_connection(spawn_image, host, port, atomic_guid)))
            if not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
                events.append(("dns_query", _make_dns_query(spawn_image, host, atomic_guid)))

        # EventID 13 — registry writes
        for reg_path, value_name, value_data in _detect_registry_writes(command):
            details = value_data or f"({value_name or 'value'})"
            events.append(("registry_set",
                           _make_registry_set(spawn_image, reg_path + ("\\" + value_name if value_name else ""), details, atomic_guid)))
        return events

    if platform in ("linux", "macos"):
        spec = (LINUX_EXECUTORS if platform == "linux" else MACOS_EXECUTORS).get(executor_name)
        if not spec:
            return []
        _, parent_image = spec
        spawn_image = _extract_linux_spawn(command) or parent_image
        events.append(("process_creation", _make_linux_process_creation(spawn_image, command, parent_image)))
        return events

    return []


def event_to_keyvalue(event: dict) -> str:
    parts = []
    for key, value in event.items():
        v = str(value).replace('"', '\\"')
        if any(c.isspace() for c in v) or "\\" in v or "=" in v or "," in v or ":" in v:
            parts.append(f'{key}="{v}"')
        else:
            parts.append(f"{key}={v}")
    return " ".join(parts)


# ── Walking the atomics tree ───────────────────────────────────────────────

def collect_atomic_samples(atomics_dir: Path) -> list[dict]:
    """Walk atomics/T*/T*.yaml. Yields one record per (atomic_test, event)."""
    samples: list[dict] = []
    for tech_dir in sorted(atomics_dir.iterdir()):
        if not tech_dir.is_dir() or not tech_dir.name.startswith("T"):
            continue
        yaml_path = tech_dir / f"{tech_dir.name}.yaml"
        if not yaml_path.exists():
            continue
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        technique = (data or {}).get("attack_technique")
        display = (data or {}).get("display_name", "")
        for test in (data or {}).get("atomic_tests", []) or []:
            executor = test.get("executor") or {}
            name = executor.get("name") or ""
            command = executor.get("command") or ""
            if not command:
                continue
            input_arguments = test.get("input_arguments") or {}
            resolved = resolve_args(command, input_arguments)
            elevation = bool(executor.get("elevation_required"))
            platforms = test.get("supported_platforms") or []
            for platform in platforms:
                events = make_event_samples(
                    name, resolved, platform,
                    test.get("auto_generated_guid") or "",
                    input_arguments, elevation,
                    technique_id=technique or "",
                )
                for subtype, event in events:
                    samples.append({
                        "technique_id":    technique,
                        "technique_name":  display,
                        "test_name":       test.get("name") or "atomic-test",
                        "test_guid":       test.get("auto_generated_guid") or "",
                        "platform":        platform,
                        "executor":        name,
                        "command":         resolved.strip(),
                        "subtype":         subtype,
                        "sample_event_kv": event_to_keyvalue(event),
                    })
    return samples


# ── Schema migration ───────────────────────────────────────────────────────

def ensure_source_column(conn) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(validation_cases)").fetchall()}
    if "source" not in cols:
        conn.execute("ALTER TABLE validation_cases ADD COLUMN source TEXT DEFAULT 'manual'")
    if "source_ref" not in cols:
        conn.execute("ALTER TABLE validation_cases ADD COLUMN source_ref TEXT")
    if "platform" not in cols:
        conn.execute("ALTER TABLE validation_cases ADD COLUMN platform TEXT")


# ── Token matching: which detections to link a sample to ───────────────────

STOP_TOKENS = {
    "windows", "linux", "macos", "powershell", "cmd", "bash", "selection",
    "condition", "detection", "title", "image", "commandline", "true", "false",
    "system32", "user", "users", "program", "files", "exe", "exec", "command",
    "process", "creation", "ext", "this", "that", "with", "from", "into",
    "atomic", "test", "red", "team", "attack", "the", "for", "and", "not",
    "filter", "select", "level", "high", "medium", "low", "critical",
    "powershellexe", "cmdexe", "registry", "value", "data", "name",
    "default", "param", "args", "argument", "string", "number",
    "windowspowershell", "winlog", "channel", "event_data",
    "subject", "target", "source", "object", "host", "machine", "domain",
    "type", "category", "logsource", "product", "service", "tags", "attackt",
    "experimental", "stable", "draft", "modified", "author", "references",
    "description", "falsepositives",
}


def _tokenize(text: str) -> set[str]:
    out: set[str] = set()
    for tok in re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{3,}", text or ""):
        t = tok.lower().strip("._-")
        if len(t) < 4 or t in STOP_TOKENS:
            continue
        out.add(t)
        if t.endswith("exe") and len(t) > 5:
            out.add(t[:-3])
    return out


def _rule_signature_tokens(raw_yaml: str, title: str) -> set[str]:
    tokens = _tokenize(title or "")
    try:
        data = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError:
        return tokens
    detection = data.get("detection") if isinstance(data, dict) else None
    if not isinstance(detection, dict):
        return tokens

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "condition":
                    continue
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str):
            tokens.update(_tokenize(node))

    for sel_name, sel_body in detection.items():
        if sel_name == "condition":
            continue
        walk(sel_body)
    return tokens


# Rule's expected event type, derived from logsource.category + EventID hints.
# Maps to the same subtype strings make_event_samples emits.
RULE_CATEGORY_TO_SUBTYPE = {
    "process_creation":      "process_creation",
    "file_event":            "file_create",
    "file_create":           "file_create",
    "file_change":           "file_create",
    "file_delete":           "file_create",
    "file_rename":           "file_create",
    "network_connection":    "network_connection",
    "dns_query":             "dns_query",
    "dns":                   "dns_query",
    "registry_event":        "registry_set",
    "registry_set":          "registry_set",
    "registry_add":          "registry_set",
    "registry_delete":       "registry_set",
}

# Common EventID → subtype (used when logsource.category is missing)
EVENTID_TO_SUBTYPE = {
    1: "process_creation",
    3: "network_connection",
    7: "image_load",
    10: "process_access",
    11: "file_create", 12: "registry_set", 13: "registry_set", 14: "registry_set",
    22: "dns_query",
    4104: "powershell_scriptblock",
}

# Field name → subtype hint. If any selection uses these fields, infer type.
FIELD_TO_SUBTYPE = {
    "targetfilename":       "file_create",
    "creationutctime":      "file_create",
    "targetobject":         "registry_set",
    "eventtype":            "registry_set",
    "destinationhostname":  "network_connection",
    "destinationip":        "network_connection",
    "destinationport":      "network_connection",
    "destinationisipv6":    "network_connection",
    "queryname":            "dns_query",
    "queryresults":         "dns_query",
    "scriptblocktext":      "powershell_scriptblock",
    "scriptblockid":        "powershell_scriptblock",
    "imageloaded":          "image_load",
    "signed":               "image_load",
    "signaturestatus":      "image_load",
    "grantedaccess":        "process_access",
    "calltrace":            "process_access",
    "sourceimage":          "process_access",
    "targetprocessguid":    "process_access",
}


def _rule_event_subtype(raw_yaml: str) -> str | None:
    """
    Determine what event type this rule expects. Returns one of the subtype
    strings we generate, or None if we can't tell.
    """
    try:
        data = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    logsource = data.get("logsource") or {}
    cat = str(logsource.get("category") or "").lower()
    if cat in RULE_CATEGORY_TO_SUBTYPE:
        return RULE_CATEGORY_TO_SUBTYPE[cat]
    # Field-based inference: look at the actual selection field names.
    detection = data.get("detection") or {}
    if isinstance(detection, dict):
        for sub in _find_subtype_from_fields(detection):
            return sub
        # EventID fallback
        for sel_body in detection.values():
            for eid in _find_eventids(sel_body):
                sub = EVENTID_TO_SUBTYPE.get(eid)
                if sub:
                    return sub
    return None


def _find_subtype_from_fields(node):
    """Yield subtypes inferred from any field name found in the detection."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "condition":
                continue
            # Strip modifiers like CommandLine|contains|all → CommandLine
            field = key.split("|", 1)[0].split(".", 1)[-1].lower()
            if field in FIELD_TO_SUBTYPE:
                yield FIELD_TO_SUBTYPE[field]
            yield from _find_subtype_from_fields(value)
    elif isinstance(node, list):
        for item in node:
            yield from _find_subtype_from_fields(item)


def _find_eventids(node, found=None):
    if found is None:
        found = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k.lower().startswith("eventid"):
                if isinstance(v, int):
                    found.append(v)
                elif isinstance(v, list):
                    for x in v:
                        if isinstance(x, int):
                            found.append(x)
                elif isinstance(v, str) and v.isdigit():
                    found.append(int(v))
            else:
                _find_eventids(v, found)
    elif isinstance(node, list):
        for item in node:
            _find_eventids(item, found)
    return found


# ── Linking + insert ───────────────────────────────────────────────────────

def import_samples(samples: list[dict], reset: bool = True, verbose: bool = True) -> dict:
    conn = get_connection()
    try:
        ensure_source_column(conn)
        if reset:
            # Clean up dependent simulation_results first so we don't leave
            # orphans pointing at deleted case rows.
            conn.execute("""
                DELETE FROM simulation_results
                WHERE case_id IN (SELECT case_id FROM validation_cases WHERE source = 'atomic')
            """)
            removed = conn.execute("DELETE FROM validation_cases WHERE source = 'atomic'").rowcount
            if verbose:
                print(f"removed {removed} prior atomic-sourced cases")

        det_rows = conn.execute("""
            SELECT d.detection_id, d.title, d.raw_yaml, d.platform
            FROM detections d
            WHERE d.raw_yaml IS NOT NULL AND length(d.raw_yaml) > 0
        """).fetchall()
        det_tokens: dict[int, set[str]] = {}
        det_meta: dict[int, tuple] = {}
        det_subtype: dict[int, str | None] = {}
        for row in det_rows:
            tokens = _rule_signature_tokens(row["raw_yaml"] or "", row["title"] or "")
            det_tokens[row["detection_id"]] = tokens
            det_meta[row["detection_id"]] = (row["title"] or "", (row["platform"] or "").lower())
            det_subtype[row["detection_id"]] = _rule_event_subtype(row["raw_yaml"] or "")

        rows = conn.execute("""
            SELECT dtm.technique_id, dtm.detection_id
            FROM detection_technique_mapping dtm
        """).fetchall()
        by_tech: dict[str, list[int]] = {}
        for r in rows:
            by_tech.setdefault(r["technique_id"], []).append(r["detection_id"])

        inserted = 0
        skipped_no_overlap = 0
        techniques_no_rule = 0
        per_test_cap = 3

        for sample in samples:
            tech = sample["technique_id"]
            targets = by_tech.get(tech)
            if not targets:
                techniques_no_rule += 1
                continue

            # Tokens for matching: combine command/test_name plus the event
            # subtype (so a "file_create" sample preferentially links to rules
            # mentioning file-write keywords).
            match_text = sample["command"] + " " + sample["test_name"] + " " + sample["subtype"]
            sample_tokens = _tokenize(match_text)
            if not sample_tokens:
                continue

            scored: list[tuple[int, int]] = []
            for det_id in targets:
                tokens = det_tokens.get(det_id)
                if not tokens:
                    continue
                # Event-type gating: if we know what the rule expects, only
                # offer it samples that match. process_creation rules pair with
                # EventID 1, file_event with 11, registry_event with 12/13, etc.
                rule_expects = det_subtype.get(det_id)
                if rule_expects and rule_expects != sample["subtype"]:
                    continue
                overlap = len(tokens & sample_tokens)
                if overlap < 2:
                    continue
                _, det_platform = det_meta.get(det_id, ("", ""))
                bonus = 1 if det_platform and sample["platform"] in det_platform else 0
                scored.append((overlap + bonus, det_id))

            if not scored:
                skipped_no_overlap += 1
                continue

            scored.sort(reverse=True)
            chosen = [det_id for _, det_id in scored[:per_test_cap]]

            for det_id in chosen:
                det_title = det_meta[det_id][0]
                attack_name = f"ART {tech} ({sample['subtype']}): {sample['test_name']}"
                conn.execute("""
                    INSERT INTO validation_cases
                      (detection_id, sample_event, expected_result, status,
                       attack_name, detection_title, sample_type, source,
                       source_ref, platform)
                    VALUES (?, ?, 'fire', 'untested', ?, ?, 'positive', 'atomic', ?, ?)
                """, (
                    det_id,
                    sample["sample_event_kv"],
                    attack_name,
                    det_title,
                    f"{tech}/{sample['test_guid']}/{sample['subtype']}",
                    sample["platform"],
                ))
                inserted += 1
        conn.commit()
        return {
            "event_samples_seen":  len(samples),
            "cases_inserted":      inserted,
            "techniques_no_rule":  techniques_no_rule,
            "samples_no_overlap":  skipped_no_overlap,
        }
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Import Atomic Red Team samples")
    parser.add_argument("--atomics", required=True, help="Path to the atomic-red-team atomics/ directory")
    parser.add_argument("--no-reset", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    atomics_dir = Path(args.atomics).expanduser().resolve()
    if not atomics_dir.is_dir():
        raise SystemExit(f"not a directory: {atomics_dir}")

    if not args.quiet:
        print(f"scanning {atomics_dir} ...")
    samples = collect_atomic_samples(atomics_dir)
    if not args.quiet:
        subtypes = {}
        for s in samples:
            subtypes[s['subtype']] = subtypes.get(s['subtype'], 0) + 1
        print(f"generated {len(samples)} event samples across {len({s['technique_id'] for s in samples})} techniques")
        print(f"  breakdown: {subtypes}")

    summary = import_samples(samples, reset=not args.no_reset, verbose=not args.quiet)
    print(json.dumps({**summary, "imported_at": datetime.utcnow().isoformat()}, indent=2))


if __name__ == "__main__":
    main()
