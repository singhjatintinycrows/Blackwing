"""Finding and candidate prioritisation.

Ranks what to look at / report first. Two uses:

* **Triage order** per track — the methodology priority (e.g. source review works missing
  authorization first, then reachable injection, ...). Encoded as class weights.
* **Report ordering** — confirmed findings sorted by (severity, confidence, class weight).
"""
from __future__ import annotations

from typing import Iterable

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_RANK = {"confirmed": 2, "firm": 1, "tentative": 0}

# Per-track class priority (higher = triage earlier). Mirrors each methodology's order.
CLASS_WEIGHT = {
    "source": {
        "missing-authz": 100, "idor": 100, "bola": 100,
        "injection": 90, "sqli": 90, "command-injection": 90, "ssti": 88, "path-traversal": 86,
        "auth": 80, "session": 78, "jwt": 76,
        "business-logic": 70, "race": 68,
        "ssrf": 60,
        "secrets": 55, "crypto": 52,
        "dependency": 45, "supply-chain": 45,
        "client-side": 30, "framework": 28,
    },
    "android": {
        "exported-no-permission": 100, "exported-component": 98,
        "deep-link": 90, "app-link": 88,
        "intent-redirection": 82,
        "webview": 78,
        "content-provider": 74,
        "implicit-intent": 68,
        "secrets": 60, "insecure-storage": 58,
        "network": 50, "pinning": 48,
        "native": 40, "third-party": 38,
        "resilience": 10,
    },
    "web": {
        "access-control": 100, "idor": 100,
        "sqli": 92, "ssrf": 90, "ssti": 88, "xxe": 86,
        "xss": 80, "csrf": 70, "cors": 66,
        "auth": 78, "jwt": 76, "oauth": 74,
        "business-logic": 72, "race": 68,
        "info-leak": 40,
    },
}


def class_weight(track: str, cls: str) -> int:
    return CLASS_WEIGHT.get(track, {}).get(cls, 50)


def triage_order(track: str, candidates: Iterable[dict]) -> list[dict]:
    """Order candidate dicts by the track's methodology priority (highest first)."""
    return sorted(
        candidates,
        key=lambda c: class_weight(track, c.get("cls", c.get("class", ""))),
        reverse=True,
    )


def report_order(findings: Iterable[dict]) -> list[dict]:
    """Order confirmed findings for the report: severity, then confidence, then class."""
    def key(f: dict):
        return (
            SEVERITY_RANK.get(f.get("severity", "info"), 0),
            CONFIDENCE_RANK.get(f.get("confidence", "tentative"), 0),
            class_weight(f.get("track", ""), f.get("cls", "")),
        )
    return sorted(findings, key=key, reverse=True)
