"""Thin client for the Wazuh Manager API.

Reads connection settings from environment variables:
  WAZUH_URL        e.g. https://localhost:55000
  WAZUH_USER       default: wazuh
  WAZUH_PASSWORD   default: wazuh
  WAZUH_VERIFY_SSL "true" / "false" — default false (self-signed certs are common)
"""

import os
import urllib3
import requests

# Self-signed certs are the norm on a single-node Wazuh manager; silence the noise
# only when verification is explicitly disabled.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhError(Exception):
    pass


def _config():
    url = os.getenv("WAZUH_URL", "").rstrip("/")
    if not url:
        raise WazuhError("WAZUH_URL is not set")
    return {
        "url":      url,
        "user":     os.getenv("WAZUH_USER", "wazuh"),
        "password": os.getenv("WAZUH_PASSWORD", "wazuh"),
        "verify":   os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true",
    }


def _authenticate(cfg) -> str:
    r = requests.post(
        f"{cfg['url']}/security/user/authenticate",
        auth=(cfg["user"], cfg["password"]),
        verify=cfg["verify"],
        timeout=15,
    )
    if r.status_code != 200:
        raise WazuhError(f"Wazuh auth failed ({r.status_code}): {r.text[:200]}")
    token = r.json().get("data", {}).get("token")
    if not token:
        raise WazuhError("Wazuh auth response missing token")
    return token


def fetch_all_rules() -> list:
    """Return every rule loaded by the Wazuh Manager.

    Each entry preserves the raw Wazuh shape, including the `mitre` block when
    present (`{"tactic": [...], "technique": [...], "id": ["T1059.001", ...]}`).
    """
    cfg     = _config()
    token   = _authenticate(cfg)
    headers = {"Authorization": f"Bearer {token}"}

    rules     = []
    offset    = 0
    page_size = 500
    while True:
        r = requests.get(
            f"{cfg['url']}/rules",
            headers=headers,
            params={"limit": page_size, "offset": offset},
            verify=cfg["verify"],
            timeout=30,
        )
        if r.status_code != 200:
            raise WazuhError(f"Wazuh /rules failed ({r.status_code}): {r.text[:200]}")
        payload = r.json().get("data", {})
        batch   = payload.get("affected_items", []) or []
        rules.extend(batch)
        total = payload.get("total_affected_items", len(rules))
        offset += len(batch)
        if not batch or offset >= total:
            break
    return rules
