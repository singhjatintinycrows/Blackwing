"""Engine entry point: run all matching tracks for a job and write the unified report.

Usage:
    BLACKWING_ENGINE=1 python3 -m bin.run_job <job_dir> [--mock]

Selects tracks from the job's scope (web/source/android), runs each track's stage DAG through
the shared runner, then merges findings into one report. Active/dynamic stages self-gate on
the scope authorisation decision, so this is safe to invoke before approval — gated stages
are recorded as skipped, not run.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bin import engine, report


def run(job_dir: str, mock: bool | None = None) -> dict:
    # Idempotent runs: rebuild findings/report from scratch each run so a post-approval run
    # (which re-runs passive + newly-authorised active stages) does not duplicate findings.
    for stale in ("findings.json", "report.md", "summary.json"):
        p = os.path.join(job_dir, stale)
        if os.path.exists(p):
            os.remove(p)
    ctx = engine.build_context(job_dir, mock=mock)
    stages: list[engine.Stage] = []
    tracks = []

    if ctx.scope.raw.get("targets", {}).get("source", {}).get("enabled") or ctx.scope.repo_url:
        from bin import track_source
        stages += track_source.STAGES
        tracks.append("source")
    if ctx.scope.raw.get("targets", {}).get("android", {}).get("enabled"):
        try:
            from bin import track_android
            stages += track_android.STAGES
            tracks.append("android")
        except Exception:
            pass
    if ctx.scope.raw.get("targets", {}).get("web", {}).get("enabled") or ctx.scope.in_scope_hosts:
        try:
            from bin import track_web
            stages += track_web.STAGES
            tracks.append("web")
        except Exception:
            pass

    ctx.audit.append("engagement_start", {"tracks": tracks, "job": os.path.basename(job_dir)})
    summary = engine.run_dag(ctx, stages) if stages else {"stages": [], "note": "no tracks matched"}
    summary["tracks"] = tracks
    report_path = report.build_report(job_dir, summary)
    ctx.audit.append("engagement_end", {"report": os.path.relpath(report_path, job_dir)})
    return summary


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    mock = "--mock" in sys.argv
    if not args:
        print("usage: python3 -m bin.run_job <job_dir> [--mock]", file=sys.stderr)
        sys.exit(1)
    out = run(args[0], mock=mock)
    import json
    print(json.dumps(out, indent=2))
