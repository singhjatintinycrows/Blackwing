"""Blackwing web front-end.

Routes: dev login (SSO seam), intake form, dashboard, job detail + live status, approval,
report viewer, evidence download. Uploaded APKs are magic-byte validated and zip-slip-safely
extracted before anything touches them. The GitHub token is handed straight to the secrets
store and never rendered, logged, or written to the job directory.
"""
from __future__ import annotations

import json
import os
import sys

from fastapi import FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from orchestrator import jobs as jobs_mod, unpack
from web.app import auth
from web.app.engine_runner import is_running, launch

APP_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))
MAX_UPLOAD_MB = int(os.environ.get("BLACKWING_MAX_UPLOAD_MB", "200"))

app = FastAPI(title="Blackwing")
app.add_middleware(SessionMiddleware,
                   secret_key=os.environ.get("BLACKWING_SECRET_KEY", "dev-only-change-me"))
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")


def _ctx(request: Request, **kw):
    user = auth.current_user(request)
    return {"request": request, "user": user, "is_reviewer": auth.is_reviewer(user or ""), **kw}


@app.get("/", response_class=HTMLResponse)
def index():
    return RedirectResponse("/dashboard", status_code=302)


# --- auth (dev SSO seam) ----------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", _ctx(request))


@app.post("/login")
def login(request: Request, identity: str = Form(...)):
    identity = identity.strip()
    if not identity:
        return RedirectResponse("/login", status_code=302)
    request.session["user"] = identity
    return RedirectResponse("/dashboard", status_code=302)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


# --- intake -----------------------------------------------------------------
@app.get("/submit", response_class=HTMLResponse)
def submit_form(request: Request):
    if not auth.current_user(request):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "intake.html", _ctx(request))


@app.post("/submit")
async def submit(
    request: Request,
    authority_reference: str = Form(""),
    web_domain: str = Form(""),
    source_repo_url: str = Form(""),
    github_token: str = Form(""),
    apk_url: str = Form(""),
    apk_file: UploadFile | None = None,
    terminal_recording: str = Form(""),
    screen_recording: str = Form(""),
):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    apk_source = apk_url.strip()
    tmp_apk = None
    try:
        # Handle an uploaded APK: size + magic-byte validation before it is trusted.
        if apk_file is not None and apk_file.filename:
            data = await apk_file.read()
            if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
                return _error(request, f"upload exceeds {MAX_UPLOAD_MB} MB")
            os.makedirs(os.path.join(_ROOT, "jobs", "_incoming"), exist_ok=True)
            tmp_apk = os.path.join(_ROOT, "jobs", "_incoming", os.path.basename(apk_file.filename))
            with open(tmp_apk, "wb") as fh:
                fh.write(data)
            try:
                unpack.validate_kind(tmp_apk, "apk")
            except unpack.UnpackError as e:
                os.remove(tmp_apk)
                return _error(request, f"rejected upload: {e}")

        job = jobs_mod.create_job(
            requester=user,
            authority_reference=authority_reference,
            web_domain=web_domain,
            source_repo_url=source_repo_url,
            github_token=github_token,          # -> secrets store, never persisted
            android_apk_source=apk_source or (tmp_apk or ""),
            terminal_recording=bool(terminal_recording),
            screen_recording=bool(screen_recording),
        )
    except jobs_mod.JobValidationError as e:
        return _error(request, str(e))

    # Move a validated upload into the job's artifacts and extract it safely.
    if tmp_apk:
        dest_apk = os.path.join(job.dir, "artifacts", os.path.basename(tmp_apk))
        os.replace(tmp_apk, dest_apk)
        try:
            unpack.safe_extract_zip(dest_apk, os.path.join(job.dir, "artifacts", "apk_decoded"))
        except unpack.UnpackError:
            pass  # recon stage will report if the manifest is unreadable
        job.targets.android_apk_source = dest_apk
        jobs_mod.write_scope(job)

    # Kick off the passive/static stages immediately; active stages self-gate until approval.
    launch(job.dir)
    return RedirectResponse(f"/jobs/{job.id}", status_code=302)


# --- dashboard + job views --------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not auth.current_user(request):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "dashboard.html", _ctx(request, jobs=jobs_mod.list_jobs()))


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: str):
    if not auth.current_user(request):
        return RedirectResponse("/login", status_code=302)
    job = jobs_mod.load_job(job_id)
    if not job:
        return _error(request, "job not found", code=404)
    return templates.TemplateResponse(request, "job.html", _ctx(
        request, job=job.to_public_dict(), status=_job_status(job.dir),
        findings=_load_json(os.path.join(job.dir, "findings.json"), []),
        running=is_running(job_id)))


@app.get("/jobs/{job_id}/status.json")
def job_status(request: Request, job_id: str):
    if not auth.current_user(request):
        return JSONResponse({"error": "auth"}, status_code=401)
    job = jobs_mod.load_job(job_id)
    if not job:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"running": is_running(job_id), **_job_status(job.dir)})


@app.post("/jobs/{job_id}/approve")
def approve(request: Request, job_id: str):
    user = auth.current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if not auth.is_reviewer(user):
        return _error(request, "only a designated reviewer may approve an engagement", code=403)
    job = jobs_mod.load_job(job_id)
    if not job:
        return _error(request, "job not found", code=404)
    try:
        jobs_mod.approve(job, user)
    except jobs_mod.JobValidationError as e:
        return _error(request, str(e), code=400)
    launch(job.dir)   # now the active/dynamic stages are authorised
    return RedirectResponse(f"/jobs/{job_id}", status_code=302)


@app.get("/jobs/{job_id}/report", response_class=HTMLResponse)
def report_view(request: Request, job_id: str):
    if not auth.current_user(request):
        return RedirectResponse("/login", status_code=302)
    job = jobs_mod.load_job(job_id)
    if not job:
        return _error(request, "job not found", code=404)
    path = os.path.join(job.dir, "report.md")
    md = open(path, encoding="utf-8").read() if os.path.exists(path) else "_No report yet._"
    return templates.TemplateResponse(request, "report.html", _ctx(request, job=job.to_public_dict(), md=md))


# --- helpers ----------------------------------------------------------------
def _job_status(job_dir: str) -> dict:
    summary = _load_json(os.path.join(job_dir, "summary.json"), {})
    stages = []
    audit_path = os.path.join(job_dir, "command_log.jsonl")
    last_cmd = ""
    if os.path.exists(audit_path):
        with open(audit_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                    stages.append(e.get("stage"))
                    last_cmd = e.get("command", last_cmd)
                except json.JSONDecodeError:
                    continue
    return {"summary": summary, "stages_seen": stages[-12:], "last_command": last_cmd}


def _load_json(path: str, default):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except json.JSONDecodeError:
            return default
    return default


def _error(request: Request, message: str, code: int = 400):
    return templates.TemplateResponse(request, "error.html", _ctx(request, message=message), status_code=code)
