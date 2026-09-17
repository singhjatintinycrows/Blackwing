"""Blackwing web front-end — simple single-step intake.

Paste a target URL, optionally add an authentication token, click Start. Blackwing auto-routes
the URL (GitHub → source review, .apk → Android, else web app), runs the assessment, and shows
the findings. The engine is detection/confirmation-only regardless. Nothing here is hardcoded:
ports, upload limits, and the model all come from the environment.
"""
from __future__ import annotations

import json
import os
import sys

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from orchestrator import jobs as jobs_mod
from orchestrator.queue import get_queue

APP_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))

app = FastAPI(title="Blackwing")
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")


def _running(job_id: str) -> bool:
    return get_queue().is_active(job_id)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html",
                                      {"request": request, "recent": jobs_mod.list_jobs()[:8]})


@app.post("/start")
def start(request: Request, url: str = Form(""), token: str = Form("")):
    try:
        job = jobs_mod.create_from_url(url, token)
    except jobs_mod.JobValidationError as e:
        return templates.TemplateResponse(request, "index.html",
                                          {"request": request, "error": str(e),
                                           "recent": jobs_mod.list_jobs()[:8]}, status_code=400)
    get_queue().enqueue(job.id)
    return RedirectResponse(f"/a/{job.id}", status_code=302)


@app.get("/a/{job_id}", response_class=HTMLResponse)
def assessment(request: Request, job_id: str):
    job = jobs_mod.load_job(job_id)
    if not job:
        return templates.TemplateResponse(request, "index.html",
                                          {"request": request, "error": "assessment not found"},
                                          status_code=404)
    return templates.TemplateResponse(request, "assessment.html", {
        "request": request, "job": job.to_public_dict(),
        "track": job.targets.active_tracks()[0] if job.targets.active_tracks() else "—",
        "target": (job.targets.web_domain or job.targets.source_repo_url
                   or job.targets.android_apk_source),
        "findings": _load_json(os.path.join(job.dir, "findings.json"), []),
        "evidence": _evidence_files(job.dir),
        "running": _running(job_id)})


@app.get("/a/{job_id}/status.json")
def status(request: Request, job_id: str):
    job = jobs_mod.load_job(job_id)
    if not job:
        return JSONResponse({"error": "not found"}, status_code=404)
    summary = _load_json(os.path.join(job.dir, "summary.json"), {})
    stages, last = [], ""
    clog = os.path.join(job.dir, "command_log.jsonl")
    if os.path.exists(clog):
        with open(clog, encoding="utf-8") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                    stages.append(e.get("stage"))
                    last = e.get("command", last)
                except json.JSONDecodeError:
                    continue
    return JSONResponse({"running": _running(job_id), "summary": summary,
                         "stages_seen": stages[-14:], "last_command": last,
                         "findings": len(_load_json(os.path.join(job.dir, "findings.json"), []))})


@app.get("/a/{job_id}/report", response_class=HTMLResponse)
def report_view(request: Request, job_id: str):
    job = jobs_mod.load_job(job_id)
    if not job:
        return RedirectResponse("/", status_code=302)
    path = os.path.join(job.dir, "report.md")
    md = open(path, encoding="utf-8").read() if os.path.exists(path) else "_No report yet._"
    return templates.TemplateResponse(request, "report.html",
                                      {"request": request, "job": job.to_public_dict(), "md": md})


@app.get("/a/{job_id}/evidence/{path:path}")
def evidence_download(request: Request, job_id: str, path: str):
    job = jobs_mod.load_job(job_id)
    if not job:
        return RedirectResponse("/", status_code=302)
    base = os.path.realpath(os.path.join(job.dir, "evidence"))
    target = os.path.realpath(os.path.join(base, path))
    if target != base and not target.startswith(base + os.sep):
        return JSONResponse({"error": "invalid path"}, status_code=400)
    if not os.path.isfile(target):
        return JSONResponse({"error": "not found"}, status_code=404)
    return FileResponse(target, filename=os.path.basename(target))


def _evidence_files(job_dir: str) -> list[dict]:
    base = os.path.join(job_dir, "evidence")
    out = []
    for dp, _dn, fn in os.walk(base):
        for f in fn:
            full = os.path.join(dp, f)
            out.append({"path": os.path.relpath(full, base), "size": os.path.getsize(full)})
    return sorted(out, key=lambda e: e["path"])


def _load_json(path: str, default):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except json.JSONDecodeError:
            return default
    return default
