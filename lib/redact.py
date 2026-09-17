"""Secret redaction — shared by hooks, audit log, command log, and reports.

The rule everywhere in Blackwing: a secret is reported by *location and kind*, never by
value. This module provides the single canonical redactor. It is deliberately conservative
(false positives are fine — a redacted non-secret costs nothing; a leaked secret is
unrecoverable).
"""
from __future__ import annotations

import re
from typing import Iterable, Pattern, Tuple

# (label, compiled pattern). Order matters: more specific first.
_PATTERNS: list[Tuple[str, Pattern[str]]] = [
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github_fine_grained", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{20,}")),
    ("aws_bedrock_bearer", re.compile(r"ABSK[A-Za-z0-9+/=]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("bearer_header", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-+/=]{20,}")),
    ("basic_auth_url", re.compile(r"https?://[^:@/\s]+:[^@/\s]+@")),
    ("generic_secret_assign", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[=:]\s*['\"]?[A-Za-z0-9._\-+/=]{12,}")),
]

_REPLACEMENT = "«REDACTED:{label}»"


def redact(text: str) -> str:
    """Return *text* with every recognised secret replaced by a kind-labelled marker."""
    if not text:
        return text
    out = text
    for label, pat in _PATTERNS:
        out = pat.sub(_REPLACEMENT.format(label=label), out)
    return out


def contains_secret(text: str) -> list[str]:
    """Return the list of secret *kinds* present in *text* (empty if none)."""
    if not text:
        return []
    found: list[str] = []
    for label, pat in _PATTERNS:
        if pat.search(text):
            found.append(label)
    return found


def redact_obj(obj):
    """Recursively redact strings inside dicts/lists/tuples for structured logging."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact_obj(v) for v in obj)
    return obj


def register_extra_secrets(values: Iterable[str]) -> None:
    """Register concrete secret literals (e.g. a job's supplied token) for exact redaction.

    The orchestrator calls this with the live token for a job so it is scrubbed even if it
    doesn't match a generic pattern. Values shorter than 8 chars are ignored to avoid
    redacting everything.
    """
    for v in values:
        if v and len(v) >= 8:
            _PATTERNS.insert(0, ("registered_secret", re.compile(re.escape(v))))
