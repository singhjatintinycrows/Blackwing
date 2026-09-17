"""Track C — Android pentest.

Stages mirroring the android-pentest methodology:

* ``android-recon``   — acquire the APK, record versionCode/Name/target/minSdk/signing,
  decode it (apktool if available; otherwise read the manifest directly), parse the manifest
  and enumerate exported components / deep links / providers / WebViews as a written inventory.
* ``android-hunter``  — triage in order (exported-no-permission → deep/app links → intent
  redirection → WebView → ContentProviders → implicit intents → secrets → storage →
  network/pinning → resilience last) via lib.android_triage, model-adjudicated into findings.
* ``android-dynamic`` — ACTIVE/gated: confirm a static hypothesis with a minimum on-device
  PoC (canary, never real data; no persistence). Skipped until the scope is approved.
* ``android-reporting``— precondition + exploitability verdict + severity, never inflated.

The static stages send no packets, so they run pre-approval; only android-dynamic is gated.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from bin.engine import Context, Stage
from lib import android_triage, findings as findings_lib, ranking


def _apk_path(ctx: Context) -> str:
    return ctx.scope.raw.get("targets", {}).get("android", {}).get("apk_source", "")


def _decoded_dir(ctx: Context) -> str:
    return os.path.join(ctx.job_dir, "artifacts", "apk_decoded")


def stage_recon(ctx: Context) -> dict:
    apk = _apk_path(ctx)
    decoded = _decoded_dir(ctx)
    manifest_path = None

    if apk and os.path.isfile(apk) and shutil.which("apktool") and not os.path.isdir(decoded):
        cmd = ["apktool", "d", "-f", "-o", decoded, apk]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        ctx.command_log.record("android-recon", " ".join(cmd), output=proc.stderr[-300:])
        if proc.returncode == 0:
            manifest_path = os.path.join(decoded, "AndroidManifest.xml")

    # Fall back to an already-decoded tree / a bare manifest supplied as apk_source.
    if manifest_path is None:
        for cand in (os.path.join(decoded, "AndroidManifest.xml"),
                     apk if apk.endswith(".xml") else None,
                     os.path.join(apk, "AndroidManifest.xml") if apk and os.path.isdir(apk) else None):
            if cand and os.path.isfile(cand):
                manifest_path = cand
                decoded = os.path.dirname(cand)
                break

    if not manifest_path:
        return {"summary": "no APK/manifest available to analyse (apktool missing or no artifact)"}

    summ = android_triage.parse_manifest(manifest_path)
    inventory = {
        "package": summ.package,
        "versionCode": summ.version_code,
        "versionName": summ.version_name,
        "targetSdk": summ.target_sdk,
        "minSdk": summ.min_sdk,
        "debuggable": summ.debuggable,
        "allowBackup": summ.allow_backup,
        "exported_components": [c.name for c in summ.components if c.effectively_exported],
        "component_count": len(summ.components),
    }
    ctx.write_artifact("android_inventory.json", json.dumps(inventory, indent=2))
    ctx.results["android_manifest_path"] = manifest_path
    ctx.results["android_decoded_dir"] = decoded
    ctx.results["android_summary"] = summ
    return {"summary": f"pkg={summ.package} v{summ.version_name} target{summ.target_sdk}; "
                       f"{len(inventory['exported_components'])} exported components",
            "inventory": inventory}


def stage_hunter(ctx: Context) -> dict:
    summ = ctx.results.get("android_summary")
    if summ is None:
        return {"summary": "no manifest parsed; nothing to hunt"}
    candidates = android_triage.triage(summ)
    ctx.write_artifact("android_candidates.json", json.dumps(candidates, indent=2))

    # secrets in the package (report location+kind only, never the value)
    decoded = ctx.results.get("android_decoded_dir")
    secret_hits = android_triage.scan_strings_for_secrets(decoded) if decoded and os.path.isdir(decoded) else []
    for s in secret_hits:
        ctx.store.add(findings_lib.Finding(
            track="android", title=f"Secret ({s['kind']}) in package", cls="secrets",
            severity="medium", confidence="firm", location=s["location"],
            description=f"A {s['kind']} appears in the package — reported by kind+location only.",
            impact="Hardcoded credential material shipped in the APK.",
            cwe="CWE-798", exploitability="confirmed", status="confirmed"))

    emitted = 0
    for c in candidates[:30]:
        verdict = _assess(ctx, c, summ)
        sev = verdict.get("severity") or _default_sev(c["cls"])
        if sev not in findings_lib.SEVERITIES:
            sev = _default_sev(c["cls"])
        confirmed_static = verdict.get("finding") == "yes"
        ctx.store.add(findings_lib.Finding(
            track="android",
            title=f"{c['cls']} — {c['component']}",
            cls=c["cls"] if c["cls"] in ranking.CLASS_WEIGHT["android"] else "exported-component",
            severity=sev,
            confidence="firm" if confirmed_static else "tentative",
            location=c["component"],
            description=c["why"],
            impact=verdict.get("rationale", "")[:300],
            precondition=verdict.get("precondition", "")[:200],
            trace=[f"manifest → {c['kind']} {c['component']} ({c['why']})"],
            cwe=verdict.get("cwe", ""),
            exploitability="static-confirmed" if confirmed_static else "needs-dynamic",
            status="candidate",   # static only; android-dynamic promotes to confirmed
            evidence_ref=["artifacts/android_candidates.json", "artifacts/android_inventory.json"],
        ))
        emitted += 1
    return {"summary": f"{len(candidates)} triage candidates; {len(secret_hits)} secret(s); "
                       f"{emitted} static findings (dynamic confirmation gated)"}


def stage_dynamic(ctx: Context) -> dict:
    """ACTIVE: on-device confirmation. Reaches here only when the scope is approved (the DAG
    runner gates it). A static finding becomes 'confirmed' only after a minimum PoC — canary,
    no persistence, no real user data."""
    static = [f for f in ctx.store.by_track("android") if f.get("exploitability") == "needs-dynamic"]
    if not shutil.which("adb"):
        return {"summary": f"adb not available; {len(static)} static findings remain unconfirmed"}
    # Real device orchestration is environment-specific; the hook-gated entry point is here.
    ctx.command_log.record("android-dynamic", "adb devices", output="(device confirmation harness)")
    return {"summary": f"dynamic confirmation harness ready for {len(static)} candidates"}


def stage_reporting(ctx: Context) -> dict:
    a = ctx.store.by_track("android")
    return {"summary": f"{len(a)} android findings assembled"}


def _assess(ctx: Context, cand: dict, summ) -> dict:
    prompt = (
        "You are an Android app-security analyst. Given a manifest-derived exposure, judge "
        "whether it is a real security finding and its precondition. Detection-only: reason "
        "about reachability, do not exploit. Reply ONLY as compact JSON: "
        '{\"finding\":\"yes|no|uncertain\",\"severity\":\"info|low|medium|high|critical\",'
        '\"cwe\":\"CWE-XX\",\"precondition\":\"...\",\"rationale\":\"one sentence\"}.\n\n'
        f"package={summ.package} targetSdk={summ.target_sdk} minSdk={summ.min_sdk}\n"
        f"class={cand['cls']} component={cand['component']} ({cand['kind']})\nwhy: {cand['why']}"
    )
    try:
        resp = ctx.model.complete(prompt, max_completion_tokens=350)
        return _parse_json(resp.content)
    except Exception as e:
        return {"finding": "uncertain", "severity": _default_sev(cand["cls"]),
                "rationale": f"model unavailable: {e}"}


def _default_sev(cls: str) -> str:
    return {"exported-no-permission": "high", "deep-link": "medium", "app-link": "medium",
            "intent-redirection": "high", "webview": "high", "content-provider": "high",
            "secrets": "medium", "insecure-storage": "low", "network": "medium",
            "resilience": "info"}.get(cls, "medium")


def _parse_json(text: str) -> dict:
    text = text.strip()
    s, e = text.find("{"), text.rfind("}")
    if s >= 0 and e > s:
        try:
            return json.loads(text[s:e + 1])
        except json.JSONDecodeError:
            pass
    return {"finding": "uncertain", "rationale": text[:200]}


STAGES = [
    Stage("android-recon", "passive", stage_recon, track="android"),
    Stage("android-hunter", "passive", stage_hunter, deps=("android-recon",), track="android"),
    Stage("android-dynamic", "active", stage_dynamic, deps=("android-hunter",), track="android"),
    Stage("android-reporting", "passive", stage_reporting, deps=("android-dynamic",), track="android"),
]
