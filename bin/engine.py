"""Engine context + DAG runner shared by all three tracks.

A ``Stage`` has a name, a kind (``passive``/``active``), a set of dependencies, and a
callable ``run(ctx)``. The runner executes stages in dependency order. Before each stage it:

* sets ``BLACKWING_STAGE`` so the hooks know which stage is asking,
* consults the scope authorisation decision — passive stages always run; active stages run
  only when ``scope.allows_stage`` says so, otherwise they are recorded as ``skipped:
  awaiting-approval`` (never silently executed),
* records start/end in the command log and hash-chained audit log.

The context gives stages the job dir, scope, model client, finding store, validation ledger,
and a ``command_log`` sink. Everything is written under ``jobs/<id>/``.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib import audit, findings as findings_lib, model_client, redact, scope as scopelib
from lib import validation


@dataclass
class Stage:
    name: str
    kind: str                      # "passive" or "active"
    run: Callable[["Context"], dict]
    deps: tuple[str, ...] = ()
    track: str = ""


class CommandLog:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def record(self, stage: str, command: str, output: str = "", **extra) -> None:
        entry = {
            "ts": round(time.time(), 3),
            "stage": stage,
            "command": redact.redact(command),
            "output_preview": redact.redact((output or "")[:500]),
            **redact.redact_obj(extra),
        }
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")


@dataclass
class Context:
    job_dir: str
    scope: scopelib.Scope
    model: model_client.ModelClient
    store: findings_lib.FindingStore
    ledger: validation.Ledger
    audit: audit.AuditLog
    command_log: CommandLog
    artifacts_dir: str = ""
    results: dict = field(default_factory=dict)

    def artifact_path(self, name: str) -> str:
        os.makedirs(self.artifacts_dir, exist_ok=True)
        return os.path.join(self.artifacts_dir, name)

    def write_artifact(self, name: str, content: str) -> str:
        p = self.artifact_path(name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(redact.redact(content))
        return p


def build_context(job_dir: str, *, mock: Optional[bool] = None) -> Context:
    scope_path = os.path.join(job_dir, "scope.yaml")
    sc = scopelib.load(scope_path)
    os.environ["BLACKWING_SCOPE"] = scope_path
    os.environ["BLACKWING_JOB_DIR"] = job_dir
    return Context(
        job_dir=job_dir,
        scope=sc,
        model=model_client.ModelClient(mock=mock),
        store=findings_lib.open_store(job_dir),
        ledger=validation.Ledger(),
        audit=audit.open_log(job_dir),
        command_log=CommandLog(os.path.join(job_dir, "command_log.jsonl")),
        artifacts_dir=os.path.join(job_dir, "artifacts"),
    )


def _toposort(stages: list[Stage]) -> list[Stage]:
    by_name = {s.name: s for s in stages}
    seen: set[str] = set()
    order: list[Stage] = []

    def visit(s: Stage, path: tuple[str, ...] = ()):
        if s.name in seen:
            return
        if s.name in path:
            raise ValueError(f"cycle in stage graph at {s.name}")
        for d in s.deps:
            if d in by_name:
                visit(by_name[d], path + (s.name,))
        seen.add(s.name)
        order.append(s)

    for s in stages:
        visit(s)
    return order


def run_dag(ctx: Context, stages: list[Stage]) -> dict:
    """Execute stages in dependency order, honouring the passive/active authorisation gate."""
    summary: dict = {"stages": [], "started_at": round(time.time(), 3)}
    for stage in _toposort(stages):
        os.environ["BLACKWING_STAGE"] = stage.name
        allowed, reason = ctx.scope.allows_stage(stage.name)
        if stage.kind == "active" and not allowed:
            ctx.audit.append("stage_skipped", {"stage": stage.name, "reason": reason})
            ctx.command_log.record(stage.name, "(stage gated)", output=reason)
            summary["stages"].append({"stage": stage.name, "status": "skipped", "reason": reason})
            continue
        ctx.audit.append("stage_start", {"stage": stage.name, "kind": stage.kind})
        t0 = time.time()
        try:
            result = stage.run(ctx) or {}
            status = "ok"
        except Exception as e:  # a stage failure must not abort the whole engagement
            result = {"error": str(e), "trace": traceback.format_exc()[-800:]}
            status = "error"
            ctx.audit.append("stage_error", {"stage": stage.name, "error": str(e)})
        dt = round(time.time() - t0, 3)
        ctx.audit.append("stage_end", {"stage": stage.name, "status": status, "seconds": dt})
        ctx.results[stage.name] = result
        summary["stages"].append(
            {"stage": stage.name, "status": status, "seconds": dt,
             "summary": result.get("summary", "")})
    summary["finished_at"] = round(time.time(), 3)
    ok, broken = ctx.audit.verify()
    summary["audit_intact"] = ok
    if not ok:
        summary["audit_broken_at"] = broken
    return summary
