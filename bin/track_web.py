"""Track A — web application pentest.

A representative slice of the swiftPentest stage graph. Passive OSINT (no packets to the
target app — DNS/records only, dorking stripped by dorking_guard) runs immediately; every
active stage (active-web probing, nuclei-hunter, validation) is gated by the DAG runner on
scope approval and recorded as skipped until then. Findings from active stages are proven by
control-contrast + N-of-M, never by causing real impact.

This is intentionally a scaffold for the specialist runners tracked in issue #7 — the gate,
logging, and reporting wiring are real; the deep per-class specialists (xss/sqli/ssrf/ssti/
idor) attach as additional active Stages.
"""
from __future__ import annotations

import json
import os
import socket
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bin.engine import Context, Stage
from lib import findings as findings_lib


def _domain(ctx: Context) -> str:
    return ctx.scope.raw.get("targets", {}).get("web", {}).get("domain", "")


def stage_passive_osint(ctx: Context) -> dict:
    """Passive: resolve DNS for in-scope hosts. No connection to the target application."""
    hosts = ctx.scope.in_scope_hosts or ([_domain(ctx)] if _domain(ctx) else [])
    records = {}
    for h in hosts:
        try:
            infos = socket.getaddrinfo(h, None)
            records[h] = sorted({i[4][0] for i in infos})
        except OSError as e:
            records[h] = f"resolution failed: {e}"
    ctx.write_artifact("web_passive_osint.json", json.dumps(records, indent=2))
    ctx.command_log.record("01-passive-osint", f"resolve {hosts}", output=json.dumps(records)[:300])
    return {"summary": f"resolved {len(hosts)} in-scope host(s)", "records": records}


def stage_active_web(ctx: Context) -> dict:
    """ACTIVE: authenticated crawling / parameter discovery against in-scope hosts only.
    Gated by the DAG runner on approval; scope_guard also denies out-of-scope hosts."""
    hosts = ctx.scope.in_scope_hosts
    ctx.command_log.record("02-active-web", f"crawl {hosts}", output="(active crawl harness)")
    return {"summary": f"active web surface enumeration ready for {len(hosts)} host(s)"}


def stage_nuclei(ctx: Context) -> dict:
    """ACTIVE: template-driven checks against confirmed in-scope hosts."""
    return {"summary": "nuclei-hunter harness ready (attach templates)"}


def stage_validation(ctx: Context) -> dict:
    """ACTIVE: control-contrast + N-of-M confirmation of active candidates before they are
    promoted to confirmed findings."""
    web = [f for f in ctx.store.by_track("web") if f.get("status") != "confirmed"]
    return {"summary": f"validation harness ready for {len(web)} web candidate(s)"}


def stage_reporting(ctx: Context) -> dict:
    return {"summary": f"{len(ctx.store.by_track('web'))} web findings assembled"}


STAGES = [
    Stage("01-passive-osint", "passive", stage_passive_osint, track="web"),
    Stage("02-active-web", "active", stage_active_web, deps=("01-passive-osint",), track="web"),
    Stage("08-nuclei-hunter", "active", stage_nuclei, deps=("02-active-web",), track="web"),
    Stage("10-validation", "active", stage_validation, deps=("08-nuclei-hunter",), track="web"),
    Stage("11-reporting", "passive", stage_reporting, deps=("10-validation",), track="web"),
]
