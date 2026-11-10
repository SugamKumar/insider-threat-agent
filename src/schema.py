"""
schema.py

Single source of truth for what a legitimate log entry looks like.

Security rationale: a blocklist (sanitizer.py) can only catch injection
phrasings someone thought of in advance. An allowlist cannot be paraphrased
around: a log field that should hold an action name, an IP or a city simply
has no business containing a sentence addressed to an AI model. Every field is
validated against its expected shape before any agent sees it, and a field that
fails is replaced with a tamper marker rather than silently passed through.
"""

import ipaddress
import re
import unicodedata
from datetime import datetime
from typing import Any

DEPARTMENTS: list[str] = ["Finance", "Engineering", "HR", "Legal", "IT", "Operations", "Sales"]

SUSPICIOUS_ACTIONS: list[str] = [
    "bulk_file_download",
    "after_hours_login",
    "unauthorized_system_access",
    "large_data_export",
    "multiple_failed_logins",
    "sensitive_file_access",
    "usb_device_connected",
    "email_forwarding_to_external",
    "vpn_from_unusual_location",
    "privilege_escalation_attempt",
]

NORMAL_ACTIONS: list[str] = [
    "file_read",
    "email_sent",
    "login",
    "logout",
    "document_edited",
    "meeting_scheduled",
]

ALL_ACTIONS: frozenset[str] = frozenset(SUSPICIOUS_ACTIONS + NORMAL_ACTIONS)

# Asset ownership: the file share each department normally works in
DEPT_SHARES: dict[str, str] = {
    "Finance": r"\\fin-share",
    "Engineering": r"\\eng-share",
    "HR": r"\\hr-share",
    "Legal": r"\\legal-share",
    "IT": r"\\it-share",
    "Operations": r"\\ops-share",
    "Sales": r"\\sales-share",
}
SENSITIVE_SHARES: list[str] = [r"\\hr-share\payroll", r"\\legal-share\m-and-a", r"\\fin-share\board"]
PERSONAL_DOMAINS: list[str] = ["gmail.com", "proton.me", "outlook.com", "yahoo.com"]

# Fields that carry labels for evaluation only — never shown to agents
HIDDEN_FIELDS: frozenset[str] = frozenset({"risk_flag", "scenario"})

TAMPER_MARKER = "[INVALID - FAILED SCHEMA VALIDATION]"

_EMP_ID = re.compile(r"^EMP-\d{4}$")
_USERNAME = re.compile(r"^[a-z0-9._-]{1,32}$")
_TICKET = re.compile(r"^CHG-\d{4}$")
_DOMAIN = re.compile(r"^(internal|[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+)$")
_RESOURCE = re.compile(r"^[A-Za-z0-9_\\/.:\- ]{1,120}$")


def _is_place_name(value: str) -> bool:
    """A city/place: letters in any script plus space ' - . , — at most 6 words, 64 chars."""
    if not 1 <= len(value) <= 64 or len(value.split()) > 6:
        return False
    return all(
        unicodedata.category(ch).startswith("L") or ch in " '-.,"
        for ch in value
    )


def _is_iso_timestamp(value: str) -> bool:
    try:
        datetime.fromisoformat(value)
        return True
    except (TypeError, ValueError):
        return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10**13


# field -> (required, validator)
FIELD_RULES: dict[str, tuple[bool, Any]] = {
    "employee_id":       (True,  lambda v: isinstance(v, str) and bool(_EMP_ID.match(v))),
    "username":          (True,  lambda v: isinstance(v, str) and bool(_USERNAME.match(v))),
    "department":        (True,  lambda v: v in DEPARTMENTS),
    "action":            (True,  lambda v: v in ALL_ACTIONS),
    "timestamp":         (True,  lambda v: isinstance(v, str) and _is_iso_timestamp(v)),
    "files_accessed":    (True,  _is_count),
    "bytes_transferred": (True,  _is_count),
    "source_ip":         (True,  lambda v: isinstance(v, str) and _is_ip(v)),
    "location":          (True,  lambda v: isinstance(v, str) and _is_place_name(v)),
    "destination":       (False, lambda v: isinstance(v, str) and bool(_DOMAIN.match(v))),
    "resource":          (False, lambda v: isinstance(v, str) and bool(_RESOURCE.match(v))),
    "ticket_id":         (False, lambda v: v is None or (isinstance(v, str) and bool(_TICKET.match(v)))),
}


def validate_log_entry(log: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """
    Validate every field of a log entry against FIELD_RULES.

    Returns a cleaned copy (invalid values replaced with TAMPER_MARKER,
    unknown fields dropped) and a list of human-readable violations.
    """
    cleaned: dict[str, Any] = {}
    violations: list[str] = []

    for field, (required, check) in FIELD_RULES.items():
        if field not in log:
            if required:
                violations.append(f"missing required field '{field}'")
                cleaned[field] = TAMPER_MARKER
            continue
        value = log[field]
        if check(value):
            cleaned[field] = value
        else:
            violations.append(f"field '{field}' failed validation")
            cleaned[field] = TAMPER_MARKER

    for field in log:
        if field in HIDDEN_FIELDS:
            cleaned[field] = log[field]          # kept for evaluation, stripped before prompting
        elif field not in FIELD_RULES:
            violations.append(f"unexpected field '{field}' dropped")

    return cleaned, violations
