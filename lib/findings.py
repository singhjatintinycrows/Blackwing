"""Unified findings schema shared across all three tracks.

Every finding carries a ``track`` field so a multi-track engagement merges into one
``findings.json``. Severity and confidence are constrained vocabularies. Evidence is a
reference into ``artifacts/`` / ``evidence/`` — never inline secret material.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Optional

TRACKS = ("web", "android", "source")
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("tentative", "firm", "confirmed")


@dataclass
class Finding:
    track: str
    title: str
    cls: str                       # vulnerability class, e.g. "idor", "sqli", "exported-activity"
    severity: str = "info"
    confidence: str = "tentative"
    # Where it lives — one of these is populated per track.
    location: str = ""             # file:line (source), host/url (web), component (android)
    description: str = ""
    impact: str = ""               # demonstrated impact only — never inflated past PoC
    precondition: str = ""
    # Detection/confirmation-only evidence trail.
    trace: list[str] = field(default_factory=list)   # source->sink steps or control-contrast
    evidence_ref: list[str] = field(default_factory=list)  # artifact/evidence paths
    cwe: str = ""
    cvss: str = ""
    exploitability: str = ""       # verdict: confirmed / plausible / refuted
    status: str = "candidate"      # candidate / confirmed / refuted
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=lambda: round(time.time(), 3))

    def __post_init__(self):
        if self.track not in TRACKS:
            raise ValueError(f"track must be one of {TRACKS}, got {self.track!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {self.severity!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"confidence must be one of {CONFIDENCES}")

    def to_dict(self) -> dict:
        return asdict(self)


class FindingStore:
    """Append findings (candidates AND refuted ones — refuted are kept, not discarded)."""

    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._items: list[dict] = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                self._items = json.load(fh)

    def add(self, finding: Finding) -> Finding:
        from . import redact
        d = redact.redact_obj(finding.to_dict())
        self._items.append(d)
        self._flush()
        return finding

    def all(self) -> list[dict]:
        return list(self._items)

    def by_track(self, track: str) -> list[dict]:
        return [f for f in self._items if f.get("track") == track]

    def _flush(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._items, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)


def open_store(job_dir: str) -> FindingStore:
    return FindingStore(os.path.join(job_dir, "findings.json"))
