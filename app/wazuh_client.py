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


def fetch_alerts(
    limit: int = 50,
    offset: int = 0,
    level: int = None,
    agent_id: str = None,
    search: str = None,
    include_archives: bool = False,
    time_from: str = None,
    time_to: str = None,
) -> dict:
    """
    Fetch alerts directly from the Wazuh Indexer (OpenSearch).

    Environment variables required:

        INDEXER_URL=https://192.168.56.102:9200
        INDEXER_USER=admin
        INDEXER_PASSWORD=<your password>
        INDEXER_VERIFY_SSL=false
    """

    indexer_url = os.getenv("INDEXER_URL", "").rstrip("/")
    if not indexer_url:
        raise WazuhError("INDEXER_URL is not set")

    user = os.getenv("INDEXER_USER", "admin")
    password = os.getenv("INDEXER_PASSWORD", "")
    verify = os.getenv("INDEXER_VERIFY_SSL", "false").lower() == "true"

    query = {
        "from": offset,
        "size": min(limit, 500),
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ]
    }

    filters = []

    if level is not None:
        filters.append({
            "range": {
                "rule.level": {
                    "gte": level,
                    "lte": 15
                }
            }
        })

    if agent_id:
        filters.append({
            "term": {
                "agent.id.keyword": agent_id
            }
        })

    if search:
        filters.append({
            "query_string": {
                "query": search
            }
        })

    if time_from or time_to:
        timestamp_range = {}
        if time_from:
            timestamp_range["gte"] = time_from
        if time_to:
            timestamp_range["lte"] = time_to
        filters.append({
            "range": {
                "@timestamp": timestamp_range
            }
        })

    if filters:
        query["query"] = {
            "bool": {
                "must": filters
            }
        }

    index = "wazuh-alerts-*,wazuh-archives-*" if include_archives else "wazuh-alerts-*"
    params = {"ignore_unavailable": "true"} if include_archives else {}

    import time as _time
    last_err = None
    for _attempt in range(3):
        try:
            r = requests.post(
                f"{indexer_url}/{index}/_search",
                auth=(user, password),
                json=query,
                params=params,
                verify=verify,
                timeout=60,
            )
            break
        except requests.exceptions.ConnectionError as e:
            last_err = e
            _time.sleep(2)
    else:
        raise WazuhError(f"Wazuh connection error: {last_err}")

    if r.status_code != 200:
        raise WazuhError(
            f"Indexer query failed ({r.status_code}): {r.text[:300]}"
        )

    payload = r.json()

    hits = payload.get("hits", {})
    total = hits.get("total", {}).get("value", 0)

    alerts = []
    seen_logs = set()

    for hit in hits.get("hits", []):

        src = hit.get("_source", {})
        full_log = src.get("full_log", "")

        if full_log and full_log in seen_logs:
            continue
        if full_log:
            seen_logs.add(full_log)

        rule = src.get("rule", {}) or {}
        agent = src.get("agent", {}) or {}
        data = src.get("data", {}) or {}
        syscheck = src.get("syscheck", {}) or {}

        alerts.append({
            "id": src.get("id", ""),
            "timestamp": src.get("@timestamp", ""),
            "rule_id": str(rule.get("id", "")),
            "rule_description": rule.get("description", ""),
            "rule_level": rule.get("level", 0),
            "rule_groups": rule.get("groups", []),
            "agent_id": str(agent.get("id", "")),
            "agent_name": agent.get("name", ""),
            "srcip": data.get("srcip", "") or (data.get("transaction") or {}).get("remote_address", ""),
            "full_log": full_log,
            # File Integrity Monitoring alerts carry the changed file in syscheck.path,
            # NOT in full_log — expose it so detections can be attributed to the exact file.
            "syscheck_path": syscheck.get("path", "") or "",
            "syscheck_event": syscheck.get("event", "") or "",
            "location": src.get("location", "")
        })

    return {
        "alerts": alerts,
        "total": total
    }


def indexer_pipeline_health(window_from: str = None) -> dict:
    """Diagnose whether the Wazuh indexer is actually able to accept new alerts.

    A validation run that reports "nothing detected" is ambiguous: it can mean a
    genuine detection gap, OR that the indexing pipeline is stalled and no alert
    of any kind is being written (the lab's classic failure: OpenSearch trips its
    flood-stage disk watermark and flips every wazuh-alerts index to read-only).

    Returns a dict the API can surface to the UI:
        healthy       — bool | None (None = could not determine)
        reason        — short human string when not healthy
        newest_alert  — @timestamp of the most recent alert in the cluster
        blocked_indices — alert indices currently read-only (write-blocked)
        disk_percent  — highest node disk-usage percent, when available

    Best-effort and defensive: any failure returns healthy=None so this never
    breaks the validation response it decorates.
    """
    indexer_url = os.getenv("INDEXER_URL", "").rstrip("/")
    if not indexer_url:
        return {"healthy": None, "reason": "INDEXER_URL not set"}
    user = os.getenv("INDEXER_USER", "admin")
    password = os.getenv("INDEXER_PASSWORD", "")
    verify = os.getenv("INDEXER_VERIFY_SSL", "false").lower() == "true"
    auth = (user, password)

    out = {"healthy": None, "reason": "", "newest_alert": None,
           "blocked_indices": [], "disk_percent": None}
    try:
        # 1) Newest alert anywhere — proves the pipeline is (or is not) writing.
        r = requests.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            auth=auth, verify=verify, timeout=20,
            json={"size": 1, "sort": [{"@timestamp": {"order": "desc"}}]},
        )
        if r.status_code == 200:
            hits = r.json().get("hits", {}).get("hits", [])
            if hits:
                out["newest_alert"] = hits[0].get("_source", {}).get("@timestamp")

        # 2) Any alert index flipped to read-only (the disk-watermark block).
        r2 = requests.get(
            f"{indexer_url}/wazuh-alerts-*/_settings/index.blocks.read_only_allow_delete"
            "?flat_settings=true",
            auth=auth, verify=verify, timeout=20,
        )
        if r2.status_code == 200:
            for idx, body in r2.json().items():
                s = body.get("settings", {}) or {}
                val = str(s.get("index.blocks.read_only_allow_delete", "")).lower()
                if val == "true":
                    out["blocked_indices"].append(idx)

        # 3) Highest node disk usage, for a helpful reason string.
        r3 = requests.get(
            f"{indexer_url}/_cat/allocation?format=json&h=disk.percent",
            auth=auth, verify=verify, timeout=20,
        )
        if r3.status_code == 200:
            pcts = [int(d["disk.percent"]) for d in r3.json()
                    if str(d.get("disk.percent", "")).isdigit()]
            if pcts:
                out["disk_percent"] = max(pcts)

        # Verdict.
        if out["blocked_indices"]:
            out["healthy"] = False
            pct = f" (disk {out['disk_percent']}%)" if out["disk_percent"] is not None else ""
            out["reason"] = (
                f"Wazuh indexer alert indices are read-only{pct} — OpenSearch "
                "disk watermark tripped, so no new alerts can be written. Free "
                "disk on the indexer VM and clear the read-only block."
            )
        elif out["disk_percent"] is not None and out["disk_percent"] >= 90:
            out["healthy"] = False
            out["reason"] = (
                f"Wazuh indexer disk is {out['disk_percent']}% full — approaching "
                "the flood-stage watermark; alert writes may stop. Free disk on "
                "the indexer VM."
            )
        elif window_from and out["newest_alert"] and out["newest_alert"] < window_from:
            out["healthy"] = False
            out["reason"] = (
                f"No Wazuh alert has been written since {out['newest_alert']}, which "
                "is before this run started — the indexing pipeline looks stalled "
                "(agent/filebeat/indexer). 'Not detected' here is unreliable."
            )
        else:
            out["healthy"] = True
    except Exception as e:  # never break the caller
        out["healthy"] = None
        out["reason"] = f"health check failed: {e}"
    return out


# ── Manager administration (used by the AI rule deployment workflow) ─────────
# These reuse the same WAZUH_URL / WAZUH_USER / WAZUH_PASSWORD configuration and
# the same bearer-token authentication as the calls above — deliberately not a
# second, unrelated connection to the manager.

_RULES_ENDPOINT = "/rules/files"


def _admin_session():
    """Return (cfg, headers) for an authenticated manager API call."""
    cfg = _config()
    token = _authenticate(cfg)
    return cfg, {"Authorization": f"Bearer {token}"}


def manager_info() -> dict:
    """Basic manager identity/version — also serves as a reachability probe."""
    cfg, headers = _admin_session()
    r = requests.get(f"{cfg['url']}/", headers=headers, verify=cfg["verify"], timeout=15)
    if r.status_code != 200:
        raise WazuhError(f"Wazuh / failed ({r.status_code}): {r.text[:200]}")
    data = r.json().get("data", {}) or {}
    return {
        "url": cfg["url"],
        "title": data.get("title"),
        "api_version": data.get("api_version"),
        "revision": data.get("revision"),
        "hostname": data.get("hostname"),
    }


def read_rule_file(filename: str) -> str | None:
    """Return the raw contents of a custom rule file, or None when absent."""
    cfg, headers = _admin_session()
    r = requests.get(
        f"{cfg['url']}{_RULES_ENDPOINT}/{filename}",
        headers=headers, params={"raw": "true"},
        verify=cfg["verify"], timeout=30,
    )
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        # A missing custom file is also reported as a resource error by some
        # manager versions — treat "does not exist" as absent, not as failure.
        if "does not exist" in r.text.lower() or "1006" in r.text:
            return None
        raise WazuhError(f"Wazuh read rule file failed ({r.status_code}): {r.text[:200]}")
    return r.text


def write_rule_file(filename: str, content: str) -> dict:
    """Upload/overwrite a custom rule file on the manager."""
    cfg, headers = _admin_session()
    headers = dict(headers)
    headers["Content-Type"] = "application/octet-stream"
    r = requests.put(
        f"{cfg['url']}{_RULES_ENDPOINT}/{filename}",
        headers=headers, params={"overwrite": "true"},
        data=content.encode("utf-8"),
        verify=cfg["verify"], timeout=60,
    )
    if r.status_code not in (200, 201):
        raise WazuhError(f"Wazuh rule file upload failed ({r.status_code}): {r.text[:400]}")
    return r.json()


def delete_rule_file(filename: str) -> None:
    """Remove a custom rule file (used to undo a first-ever deployment)."""
    cfg, headers = _admin_session()
    r = requests.delete(
        f"{cfg['url']}{_RULES_ENDPOINT}/{filename}",
        headers=headers, verify=cfg["verify"], timeout=30,
    )
    if r.status_code not in (200, 404):
        raise WazuhError(f"Wazuh rule file delete failed ({r.status_code}): {r.text[:200]}")


def validate_configuration() -> dict:
    """Ask the manager to validate its current configuration + rules.

    Returns ``{"valid": bool, "errors": [...]}``.
    """
    cfg, headers = _admin_session()
    r = requests.get(
        f"{cfg['url']}/manager/configuration/validation",
        headers=headers, verify=cfg["verify"], timeout=60,
    )
    if r.status_code not in (200, 400):
        raise WazuhError(f"Wazuh config validation failed ({r.status_code}): {r.text[:300]}")
    payload = r.json()
    data = payload.get("data", {}) or {}
    items = data.get("affected_items", []) or []
    errors = []
    for entry in data.get("failed_items", []) or []:
        error = entry.get("error", {}) or {}
        message = error.get("message", "")
        detail = error.get("remediation") or ""
        for target in entry.get("id", []) or [""]:
            errors.append(" ".join(x for x in (str(target), message, detail) if x).strip())
    valid = bool(items) and not errors
    if not items and not errors:
        # Some versions report status inside affected_items[0]["status"].
        valid = str(payload.get("message", "")).lower().find("ok") != -1
    return {"valid": valid, "errors": errors, "raw": payload}


def logtest(log: str, log_format: str = "syslog", location: str = "absega-ai-validation") -> dict:
    """Run one event through the manager's rule engine (wazuh-logtest).

    Returns ``{"ran": bool, "rule_id": str|None, "level": int|None,
    "description": str|None, "raw": ...}``. ``ran`` is False only when the
    endpoint is unavailable — it is never faked.
    """
    cfg, headers = _admin_session()
    r = requests.put(
        f"{cfg['url']}/logtest",
        headers=headers,
        json={"event": log, "log_format": log_format, "location": location},
        verify=cfg["verify"], timeout=45,
    )
    if r.status_code not in (200, 206):
        raise WazuhError(f"Wazuh logtest failed ({r.status_code}): {r.text[:300]}")
    payload = r.json()
    items = (payload.get("data", {}) or {}).get("affected_items", []) or []
    output = (items[0] if items else {}).get("output", {}) or {}
    rule = output.get("rule", {}) or {}
    token = (items[0] if items else {}).get("token")
    if token:
        # Close the session so the manager does not accumulate logtest sessions.
        try:
            requests.delete(f"{cfg['url']}/logtest/sessions/{token}",
                            headers=headers, verify=cfg["verify"], timeout=15)
        except Exception:
            pass
    return {
        "ran": True,
        "rule_id": str(rule.get("id")) if rule.get("id") is not None else None,
        "level": rule.get("level"),
        "description": rule.get("description"),
        "groups": rule.get("groups", []),
        "raw": output,
    }


def restart_manager() -> dict:
    """Restart the Wazuh manager so new rules take effect."""
    cfg, headers = _admin_session()
    r = requests.put(f"{cfg['url']}/manager/restart", headers=headers,
                     verify=cfg["verify"], timeout=90)
    # The Wazuh API restarts asynchronously and replies 202 Accepted once the
    # request is queued — 200 never actually occurs here.
    if r.status_code not in (200, 202):
        raise WazuhError(f"Wazuh restart failed ({r.status_code}): {r.text[:300]}")
    return r.json()


def manager_status() -> dict:
    """Daemon status map, used as the post-restart health check."""
    cfg, headers = _admin_session()
    r = requests.get(f"{cfg['url']}/manager/status", headers=headers,
                     verify=cfg["verify"], timeout=30)
    if r.status_code != 200:
        raise WazuhError(f"Wazuh status failed ({r.status_code}): {r.text[:200]}")
    items = (r.json().get("data", {}) or {}).get("affected_items", []) or []
    daemons = items[0] if items else {}
    critical = ("wazuh-analysisd", "wazuh-db", "wazuh-remoted")
    unhealthy = [name for name in critical
                 if name in daemons and daemons[name] != "running"]
    return {"daemons": daemons, "healthy": not unhealthy, "unhealthy": unhealthy}


def fetch_local_rule_ids() -> set:
    """Every rule ID currently loaded by the manager (for collision checks)."""
    return {int(rule["id"]) for rule in fetch_all_rules()
            if str(rule.get("id", "")).isdigit()}


def fetch_agents() -> list:
    """Return list of connected Wazuh agents."""
    cfg     = _config()
    token   = _authenticate(cfg)
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(
        f"{cfg['url']}/agents",
        headers=headers,
        params={"limit": 100, "select": "id,name,ip,status,os.name,lastKeepAlive"},
        verify=cfg["verify"],
        timeout=15,
    )
    if r.status_code != 200:
        raise WazuhError(f"Wazuh /agents failed ({r.status_code}): {r.text[:200]}")

    return r.json().get("data", {}).get("affected_items", []) or []
