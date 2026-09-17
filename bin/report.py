"""Unified, track-labelled report for an engagement.

Merges findings.json across whichever tracks ran (each finding carries its ``track``), orders
them by severity/confidence/class, and writes a human report.md plus a machine summary.json.
All output is passed through the redactor — a report never contains a raw secret.
"""
from __future__ import annotations

import json
import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib import findings as findings_lib, ranking, redact

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def build_report(job_dir: str, run_summary: dict | None = None) -> str:
    store = findings_lib.open_store(job_dir)
    all_findings = store.all()
    ordered = ranking.report_order(all_findings)
    confirmed = [f for f in ordered if f.get("status") == "confirmed"]
    candidates = [f for f in ordered if f.get("status") != "confirmed"]

    by_sev: dict[str, int] = {}
    by_track: dict[str, int] = {}
    for f in confirmed:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_track[f["track"]] = by_track.get(f["track"], 0) + 1

    lines: list[str] = []
    job_id = os.path.basename(job_dir.rstrip("/"))
    lines.append(f"# Blackwing engagement report — `{job_id}`")
    lines.append("")
    lines.append(f"_Generated {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}. "
                 "Detection- and confirmation-only: findings are proven with minimum "
                 "reproducible evidence, never real impact._")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    if confirmed:
        sev_str = ", ".join(f"{SEV_EMOJI.get(s,'')} {n} {s}"
                            for s, n in sorted(by_sev.items(),
                                               key=lambda kv: -ranking.SEVERITY_RANK.get(kv[0], 0)))
        lines.append(f"**{len(confirmed)} confirmed finding(s):** {sev_str}.")
        lines.append("")
        lines.append(f"Tracks run: {', '.join(sorted(by_track)) or '—'}. "
                     f"{len(candidates)} additional candidate(s) recorded (unconfirmed/refuted kept).")
    else:
        lines.append("No confirmed findings. "
                     f"{len(candidates)} candidate(s) recorded for review.")
    lines.append("")

    if confirmed:
        lines.append("## Confirmed findings")
        lines.append("")
        for f in confirmed:
            lines.extend(_finding_md(f))

    if candidates:
        lines.append("## Candidates (unconfirmed / refuted — kept per methodology)")
        lines.append("")
        for f in candidates:
            lines.append(f"- `{f['track']}` **{f['title']}** — {f.get('confidence')} / "
                         f"{f.get('exploitability','')} @ `{f.get('location','')}`")
        lines.append("")

    if run_summary:
        lines.append("## Run log")
        lines.append("")
        for st in run_summary.get("stages", []):
            mark = {"ok": "✓", "skipped": "⏭", "error": "✗"}.get(st.get("status"), "?")
            lines.append(f"- {mark} `{st['stage']}` — {st.get('status')} "
                         f"{st.get('summary','') or st.get('reason','')}")
        lines.append("")
        lines.append(f"_Audit chain intact: {run_summary.get('audit_intact')}._")
        lines.append("")

    report = redact.redact("\n".join(lines))
    path = os.path.join(job_dir, "report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report)

    summary = {
        "job_id": job_id,
        "confirmed": len(confirmed),
        "candidates": len(candidates),
        "by_severity": by_sev,
        "by_track": by_track,
    }
    with open(os.path.join(job_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    return path


def _finding_md(f: dict) -> list[str]:
    e = SEV_EMOJI.get(f.get("severity", "info"), "")
    out = [f"### {e} [{f['track']}] {f['title']}", ""]
    out.append(f"- **Severity:** {f.get('severity')}  |  **Confidence:** {f.get('confidence')}  "
               f"|  **Class:** `{f.get('cls')}`  |  **{f.get('cwe','')}**")
    if f.get("location"):
        out.append(f"- **Location:** `{f['location']}`")
    if f.get("precondition"):
        out.append(f"- **Precondition:** {f['precondition']}")
    if f.get("impact"):
        out.append(f"- **Impact (demonstrated):** {f['impact']}")
    if f.get("trace"):
        out.append("- **Trace:**")
        for step in f["trace"]:
            out.append(f"    - {step}")
    if f.get("evidence_ref"):
        out.append(f"- **Evidence:** {', '.join(f['evidence_ref'])}")
    out.append("")
    return out
