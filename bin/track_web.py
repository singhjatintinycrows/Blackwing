"""Track A — web application pentest (detection/confirmation-only).

The full swiftPentest-style stage graph:

  01 passive-osint → 05 threat-intel → 04 cloud-enum → 02 active-web → 03 network-discovery
  → 06 analysis-correlation → 07 attack-planner → (xss / sqli / ssti / 09 access-control /
  08 nuclei-hunter specialists) → 10 validation → 11 reporting

Passive/static stages (01, 05, 06) run immediately. Every stage that sends a packet to the
target is ACTIVE: the DAG runner gates it on scope approval, `scope_guard.sh` denies
out-of-scope hosts, and `lib/webprobe.HttpClient` re-enforces the in-scope allowlist in the
engine itself. Specialists produce *candidates* via control-contrast; stage 10 confirms them
with N-of-M repetition + a negative control before anything is reported as confirmed. Nothing
here exploits, extracts data, or causes real impact.
"""
from __future__ import annotations

import json
import os
import socket
import sys
from collections import OrderedDict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bin.engine import Context, Stage
from lib import findings as findings_lib, ranking, validation, webprobe

MAX_CRAWL = 40
MAX_TARGETS = 60


def _domain(ctx: Context) -> str:
    return ctx.scope.raw.get("targets", {}).get("web", {}).get("domain", "")


def _client(ctx: Context) -> webprobe.HttpClient:
    cli = ctx.results.get("_web_client")
    if cli is None:
        cli = webprobe.HttpClient(in_scope_hosts=ctx.scope.in_scope_hosts or [_domain(ctx)])
        ctx.results["_web_client"] = cli
    return cli


def _seeds(ctx: Context) -> list[str]:
    hosts = ctx.scope.in_scope_hosts or ([_domain(ctx)] if _domain(ctx) else [])
    seeds = []
    for h in hosts:
        if h.startswith("http"):
            seeds.append(h)
        else:
            seeds += [f"https://{h}/", f"http://{h}/"]
    return seeds


# -- passive -----------------------------------------------------------------
def stage_passive_osint(ctx: Context) -> dict:
    hosts = ctx.scope.in_scope_hosts or ([_domain(ctx)] if _domain(ctx) else [])
    records = {}
    for h in hosts:
        host = h.split("//")[-1].split("/")[0]
        try:
            records[host] = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
        except OSError as e:
            records[host] = f"resolution failed: {e}"
    ctx.write_artifact("web_passive_osint.json", json.dumps(records, indent=2))
    return {"summary": f"resolved {len(records)} host(s)", "records": records}


def stage_threat_intel(ctx: Context) -> dict:
    # Passive summary only — NO dorking (dorking_guard enforces this anyway).
    return {"summary": "threat-intel: passive context only (no dorking); attack surface from crawl"}


# -- active: recon -----------------------------------------------------------
def stage_active_web(ctx: Context) -> dict:
    """Crawl in-scope hosts, collect endpoints and their parameters."""
    cli = _client(ctx)
    seen: "OrderedDict[str, None]" = OrderedDict()
    params_by_url: dict[str, list[str]] = {}
    frontier = list(_seeds(ctx))
    fetched = 0
    reachable_seed = None
    while frontier and fetched < MAX_CRAWL:
        url = frontier.pop(0)
        if url in seen:
            continue
        seen[url] = None
        try:
            r = cli.get(url)
        except (webprobe.ScopeViolation, OSError):
            continue
        fetched += 1
        reachable_seed = reachable_seed or url
        ctx.command_log.record("02-active-web", f"GET {url}", output=f"status={r.status} len={len(r.body)}")
        ps = webprobe.params_of(url)
        if ps:
            params_by_url[url] = ps
        for link in webprobe.extract_links(url, r.body):
            host = link.split("//")[-1].split("/")[0]
            if webprobe.host_in_scope(host, cli.in_scope_hosts) and link not in seen:
                if len(seen) + len(frontier) < MAX_CRAWL:
                    frontier.append(link)
    ctx.results["web_params_by_url"] = params_by_url
    ctx.results["web_reachable_seed"] = reachable_seed
    ctx.write_artifact("web_endpoints.json", json.dumps(
        {"fetched": fetched, "parametrised_endpoints": params_by_url}, indent=2))
    return {"summary": f"crawled {fetched} URL(s); {len(params_by_url)} parametrised endpoint(s)",
            "reachable": bool(reachable_seed)}


def stage_network_discovery(ctx: Context) -> dict:
    # Light, in-scope only: confirm which seed scheme/port answered (from the crawl).
    seed = ctx.results.get("web_reachable_seed")
    return {"summary": f"reachable entry point: {seed or 'none'}"}


def stage_cloud_enum(ctx: Context) -> dict:
    """Check security-relevant response headers on the reachable seed (no exploitation)."""
    seed = ctx.results.get("web_reachable_seed")
    if not seed:
        return {"summary": "no reachable seed to inspect"}
    try:
        r = _client(ctx).get(seed)
    except (webprobe.ScopeViolation, OSError) as e:
        return {"summary": f"header inspection failed: {e}"}
    missing = [h for h in ("Content-Security-Policy", "Strict-Transport-Security",
                           "X-Content-Type-Options", "X-Frame-Options")
               if h not in {k.title(): v for k, v in r.headers.items()}]
    if missing:
        ctx.store.add(findings_lib.Finding(
            track="web", title="Missing security headers", cls="info-leak",
            severity="low", confidence="firm", location=seed,
            description="Response is missing: " + ", ".join(missing),
            impact="Weakened defence-in-depth (clickjacking/MIME/transport).",
            trace=[f"GET {seed} → response headers"], cwe="CWE-693",
            exploitability="confirmed", status="confirmed",
            evidence_ref=["artifacts/web_endpoints.json"]))
    return {"summary": f"security headers: {len(missing)} missing"}


# -- planner (passive) -------------------------------------------------------
def stage_attack_planner(ctx: Context) -> dict:
    """Build the (url, param) target list, most promising first."""
    params_by_url = ctx.results.get("web_params_by_url", {})
    targets = [(u, p) for u, ps in params_by_url.items() for p in ps]
    # heuristic: id-like params first (idor), then search/q (xss/sqli/ssti)
    def score(t):
        _, p = t
        pl = p.lower()
        if any(k in pl for k in ("id", "user", "account", "order", "file")):
            return 3
        if any(k in pl for k in ("q", "search", "name", "query", "s", "keyword")):
            return 2
        return 1
    targets.sort(key=score, reverse=True)
    ctx.results["web_targets"] = targets[:MAX_TARGETS]
    return {"summary": f"{len(targets)} (url,param) targets planned"}


# -- specialists (active) ----------------------------------------------------
def _add_candidate(ctx, cls, url, param, detail, probe, negative, sev, cwe):
    ctx.results.setdefault("web_candidates", []).append({
        "cls": cls, "url": url, "param": param, "detail": detail,
        "probe": probe, "negative": negative, "severity": sev, "cwe": cwe})


def _spec(ctx, detector, cls, sev, cwe, negative_factory):
    cli = _client(ctx)
    found = 0
    for url, param in ctx.results.get("web_targets", []):
        try:
            is_cand, detail, _ = detector(cli, url, param)
        except (webprobe.ScopeViolation, OSError):
            continue
        if is_cand:
            found += 1
            _add_candidate(ctx, cls, url, param, detail,
                           probe=lambda u=url, p=param: detector(cli, u, p)[0],
                           negative=negative_factory(cli, url, param),
                           sev=sev, cwe=cwe)
    return {"summary": f"{cls}: {found} candidate(s) from control-contrast"}


def stage_xss(ctx: Context) -> dict:
    def neg(cli, url, param):
        # negative control: a plain-text marker (no tags) must NOT appear as raw <b>marker</b>
        def _n():
            marker = "bwsafe" + webprobe._rand(5)
            r = cli.get(webprobe.with_param(url, param, marker))
            return f"<b>{marker}</b>" in r.body
        return _n
    return _spec(ctx, webprobe.detect_reflected_xss, "xss", "medium", "CWE-79", neg)


def stage_sqli(ctx: Context) -> dict:
    def neg(cli, url, param):
        # negative control: two baseline fetches should NOT diverge like a false condition
        def _n():
            a = cli.get(webprobe.with_param(url, param, "1"))
            b = cli.get(webprobe.with_param(url, param, "1"))
            return webprobe.similarity(a.body, b.body) < 0.9
        return _n
    return _spec(ctx, webprobe.detect_boolean_sqli, "sqli", "high", "CWE-89", neg)


def stage_ssti(ctx: Context) -> dict:
    def neg(cli, url, param):
        # negative control: raw "7*7" without braces must NOT yield "49"
        def _n():
            r = cli.get(webprobe.with_param(url, param, "bw7*7bw"))
            return "bw49bw" in r.body
        return _n
    return _spec(ctx, webprobe.detect_ssti, "ssti", "high", "CWE-1336", neg)


def stage_access_control(ctx: Context) -> dict:
    # IDOR/BOLA only when credentials were provided to contrast against (else structural note).
    return {"summary": "access-control: differential requires supplied credentials (none configured)"}


def stage_nuclei(ctx: Context) -> dict:
    import shutil, subprocess
    if not shutil.which("nuclei"):
        return {"summary": "nuclei not installed; skipping template checks"}
    seed = ctx.results.get("web_reachable_seed")
    if not seed:
        return {"summary": "no reachable seed for nuclei"}
    out = ctx.artifact_path("nuclei.jsonl")
    cmd = ["nuclei", "-u", seed, "-jsonl", "-o", out, "-silent", "-severity", "low,medium,high,critical"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        ctx.command_log.record("08-nuclei-hunter", " ".join(cmd), output="(nuclei run)")
    except Exception as e:
        return {"summary": f"nuclei failed: {e}"}
    return {"summary": "nuclei run complete", "output": "artifacts/nuclei.jsonl"}


# -- validation (active) -----------------------------------------------------
def stage_validation(ctx: Context) -> dict:
    cands = ctx.results.get("web_candidates", [])
    confirmed = 0
    for c in cands:
        res = validation.n_of_m_contrast(c["probe"], c["negative"], m=3, n=2)
        status = "confirmed" if res.confirmed else "candidate"
        if res.confirmed:
            confirmed += 1
        ctx.store.add(findings_lib.Finding(
            track="web",
            title=f"{c['cls']} via parameter '{c['param']}'",
            cls=c["cls"] if c["cls"] in ranking.CLASS_WEIGHT["web"] else "info-leak",
            severity=c["severity"],
            confidence="confirmed" if res.confirmed else "tentative",
            location=f"{c['url']} (param {c['param']})",
            description=c["detail"],
            impact=("Confirmed by control-contrast + N-of-M; detection-only, no exploitation."
                    if res.confirmed else "Candidate; not reproduced under N-of-M."),
            precondition=f"parameter '{c['param']}' reachable on an in-scope endpoint",
            trace=[f"probe param '{c['param']}' → control-contrast", res.detail],
            cwe=c["cwe"],
            exploitability="confirmed" if res.confirmed else "unconfirmed",
            status=status,
            evidence_ref=["artifacts/web_endpoints.json"]))
    ctx.write_artifact("web_validation.json", json.dumps(
        [{k: v for k, v in c.items() if k not in ("probe", "negative")} for c in cands], indent=2))
    return {"summary": f"{len(cands)} candidate(s); {confirmed} confirmed under N-of-M"}


def stage_reporting(ctx: Context) -> dict:
    return {"summary": f"{len(ctx.store.by_track('web'))} web findings assembled"}


STAGES = [
    Stage("01-passive-osint", "passive", stage_passive_osint, track="web"),
    Stage("05-threat-intel", "passive", stage_threat_intel, deps=("01-passive-osint",), track="web"),
    Stage("02-active-web", "active", stage_active_web, deps=("01-passive-osint",), track="web"),
    Stage("03-network-discovery", "passive", stage_network_discovery, deps=("02-active-web",), track="web"),
    Stage("04-cloud-enum", "active", stage_cloud_enum, deps=("02-active-web",), track="web"),
    Stage("07-attack-planner", "passive", stage_attack_planner, deps=("02-active-web",), track="web"),
    Stage("xss", "active", stage_xss, deps=("07-attack-planner",), track="web"),
    Stage("sqli", "active", stage_sqli, deps=("07-attack-planner",), track="web"),
    Stage("ssti", "active", stage_ssti, deps=("07-attack-planner",), track="web"),
    Stage("09-access-control", "active", stage_access_control, deps=("07-attack-planner",), track="web"),
    Stage("08-nuclei-hunter", "active", stage_nuclei, deps=("07-attack-planner",), track="web"),
    Stage("10-validation", "active", stage_validation,
          deps=("xss", "sqli", "ssti", "09-access-control"), track="web"),
    Stage("11-reporting", "passive", stage_reporting, deps=("10-validation",), track="web"),
]
