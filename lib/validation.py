"""Validation ledger — the discipline that separates a candidate from a finding.

Two mechanisms, shared by all tracks:

* **Candidate ledger** — every hypothesis is recorded with its traced path, guard analysis,
  reachability and confidence, and its verdict (confirmed / refuted). Refuted candidates are
  KEPT, not discarded — the methodology requires the negative results.
* **N-of-M control-contrast** — a finding is only "confirmed" when a discriminating signal
  reproduces on at least N of M trials AND a negative control (the same probe against a
  known-safe baseline) does NOT fire. This is what makes evidence minimum-yet-sufficient
  without ever causing real impact.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Candidate:
    hypothesis: str
    track: str
    traced_path: list[str] = field(default_factory=list)
    guard_analysis: str = ""          # what sanitiser/authz sits on the path, and whether it holds
    reachability: str = ""            # is the sink actually reachable from the source?
    confidence: str = "tentative"
    verdict: str = "open"             # open / confirmed / refuted
    evidence_ref: list[str] = field(default_factory=list)
    notes: str = ""
    ts: float = field(default_factory=lambda: round(time.time(), 3))

    def confirm(self, evidence_ref: Optional[list[str]] = None, note: str = "") -> "Candidate":
        self.verdict = "confirmed"
        self.confidence = "confirmed"
        if evidence_ref:
            self.evidence_ref.extend(evidence_ref)
        if note:
            self.notes = (self.notes + "\n" + note).strip()
        return self

    def refute(self, note: str = "") -> "Candidate":
        self.verdict = "refuted"
        if note:
            self.notes = (self.notes + "\n" + note).strip()
        return self


class Ledger:
    def __init__(self) -> None:
        self._items: list[Candidate] = []

    def record(self, candidate: Candidate) -> Candidate:
        self._items.append(candidate)
        return candidate

    def all(self) -> list[Candidate]:
        return list(self._items)

    def confirmed(self) -> list[Candidate]:
        return [c for c in self._items if c.verdict == "confirmed"]

    def refuted(self) -> list[Candidate]:
        return [c for c in self._items if c.verdict == "refuted"]

    def to_dicts(self) -> list[dict]:
        return [vars(c) for c in self._items]


@dataclass
class ContrastResult:
    positive_hits: int
    trials: int
    negative_control_fired: bool
    confirmed: bool
    detail: str = ""


def n_of_m_contrast(
    probe: Callable[[], bool],
    negative_control: Callable[[], bool],
    m: int = 5,
    n: int = 3,
) -> ContrastResult:
    """Run *probe* m times; require >= n hits. Run *negative_control* once; it must NOT fire.

    ``probe`` returns True when the discriminating signal is present, ``negative_control``
    returns True when the same signal appears against a known-safe baseline (which would mean
    the probe is non-discriminating). Neither should cause real impact — they observe a
    control-contrast, not an exploit outcome.
    """
    hits = sum(1 for _ in range(m) if probe())
    neg = bool(negative_control())
    confirmed = hits >= n and not neg
    return ContrastResult(
        positive_hits=hits,
        trials=m,
        negative_control_fired=neg,
        confirmed=confirmed,
        detail=f"{hits}/{m} positive, negative_control={'FIRED' if neg else 'clean'}",
    )
