"""Environment-driven configuration for the ABSEGA AI Detection Rule
Recommendation workflow.

Everything the Gemini integration needs is read from the process environment
(populated from ``.env`` by ``app.main``). The API key is *only* ever handed to
the Google Gen AI SDK — it is never returned by an API route, never logged,
never rendered, and never stored in the database.

``scrub_secrets()`` is the last line of defence: every string that leaves the
backend on an error path (log line, HTTP detail, stored validation result) is
passed through it, so a secret that leaks into a third-party exception message
still never reaches the client.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# ── env helpers ──────────────────────────────────────────────────────────────

_TRUTHY = {"1", "true", "yes", "on", "y"}
_FALSY = {"0", "false", "no", "off", "n"}


def _env(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    return default if raw is None else raw.strip()


def _env_int(name: str, default: int, minimum: int = 0, maximum: int | None = None) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    if maximum is not None and value > maximum:
        return maximum
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    return default


# ── Postgres settings ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DatabaseSettings:
    host: str
    port: int
    name: str
    user: str
    password: str


def database_settings() -> DatabaseSettings:
    return DatabaseSettings(
        host=_env("DB_HOST", "127.0.0.1"),
        port=_env_int("DB_PORT", 5432, minimum=1, maximum=65535),
        name=_env("DB_NAME", "detection_platform"),
        user=_env("DB_USER", "socapp"),
        password=_env("DB_PASSWORD"),
    )


# ── Gemini settings ──────────────────────────────────────────────────────────

#: Environment variable holding the Gemini API key. Referenced by name only.
API_KEY_ENV = "GEMINI_API_KEY"

PROVIDER = "gemini"


@dataclass(frozen=True, repr=False)
class GeminiSettings:
    """Immutable snapshot of the Gemini configuration.

    ``api_key`` is deliberately excluded from ``__repr__`` so the object can be
    dropped into a log line or a traceback without leaking anything.
    """

    enabled: bool
    api_key: str
    model: str
    timeout_seconds: int
    max_retries: int
    max_evidence_chars: int
    rate_limit_per_minute: int

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)

    @property
    def configured(self) -> bool:
        """True when a generation call could actually be attempted."""
        return bool(self.api_key) and bool(self.model)

    def missing(self) -> list[str]:
        """Names (never values) of the settings that still need to be provided."""
        gaps: list[str] = []
        if not self.api_key:
            gaps.append(API_KEY_ENV)
        if not self.model:
            gaps.append("GEMINI_MODEL")
        return gaps

    def unavailable_reason(self) -> str | None:
        """Human-readable reason generation cannot run, or None when it can."""
        if not self.enabled:
            return ("The Gemini provider is disabled on this server "
                    "(GEMINI_ENABLED=false).")
        gaps = self.missing()
        if gaps:
            return (f"Gemini is not configured — {', '.join(gaps)} "
                    f"{'is' if len(gaps) == 1 else 'are'} not set in the backend "
                    "environment.")
        return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"GeminiSettings(enabled={self.enabled}, model={self.model!r}, "
                f"api_key=<redacted>, timeout_seconds={self.timeout_seconds})")


def gemini_settings() -> GeminiSettings:
    """Read the current Gemini configuration from the environment.

    Deliberately uncached: the settings are cheap to build and tests (and the
    ``/api/ai/status`` route) must observe environment changes immediately.
    """
    return GeminiSettings(
        enabled=_env_bool("GEMINI_ENABLED", True),
        api_key=_env(API_KEY_ENV),
        model=_env("GEMINI_MODEL"),
        timeout_seconds=_env_int("GEMINI_TIMEOUT_SECONDS", 45, minimum=5, maximum=600),
        max_retries=_env_int("GEMINI_MAX_RETRIES", 2, minimum=0, maximum=8),
        max_evidence_chars=_env_int("GEMINI_MAX_EVIDENCE_CHARS", 12000,
                                    minimum=1000, maximum=500000),
        rate_limit_per_minute=_env_int("GEMINI_RATE_LIMIT_PER_MINUTE", 5,
                                       minimum=1, maximum=600),
    )


# ── Wazuh AI-rule deployment settings ────────────────────────────────────────

@dataclass(frozen=True)
class AiRuleDeploymentSettings:
    """Where AI-drafted Wazuh rules live and which rule IDs they may claim."""

    rules_filename: str
    rule_id_min: int
    rule_id_max: int
    restart_manager: bool

    @property
    def manager_path(self) -> str:
        return f"/var/ossec/etc/rules/{self.rules_filename}"


def deployment_settings() -> AiRuleDeploymentSettings:
    rule_id_min = _env_int("AI_WAZUH_RULE_ID_MIN", 110000, minimum=100000, maximum=999999)
    rule_id_max = _env_int("AI_WAZUH_RULE_ID_MAX", 119999, minimum=100000, maximum=999999)
    if rule_id_max <= rule_id_min:
        rule_id_max = rule_id_min + 999
    filename = _env("AI_WAZUH_RULES_FILE", "absega_ai_rules.xml") or "absega_ai_rules.xml"
    # Never allow the configured file name to escape the rules directory.
    filename = os.path.basename(filename)
    if not filename.endswith(".xml"):
        filename = "absega_ai_rules.xml"
    return AiRuleDeploymentSettings(
        rules_filename=filename,
        rule_id_min=rule_id_min,
        rule_id_max=rule_id_max,
        restart_manager=_env_bool("AI_WAZUH_RESTART_MANAGER", True),
    )


# ── Secret scrubbing ─────────────────────────────────────────────────────────

#: Environment variables whose *values* must never appear in output.
_SECRET_ENV_VARS = (
    API_KEY_ENV,
    "ANTHROPIC_API_KEY",
    "WAZUH_PASSWORD",
    "INDEXER_PASSWORD",
    "TARGET_PASSWORD",
    "DB_PASSWORD",
)


def scrub_secrets(text: str) -> str:
    """Replace any configured secret value found in *text* with a placeholder.

    Applied to every log line, HTTP error detail and persisted validation
    result produced by the AI workflow, so a secret that leaks into a
    third-party exception message never reaches a client, a log file or the
    database.
    """
    if not text:
        return text
    out = str(text)
    for name in _SECRET_ENV_VARS:
        value = os.getenv(name) or ""
        value = value.strip()
        if len(value) >= 8 and value in out:
            out = out.replace(value, f"[REDACTED_{name}]")
    return out
