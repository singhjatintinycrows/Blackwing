"""Job lifecycle: intake -> scope.yaml -> approval -> run -> report.

A Job is the unit of an engagement. Its state machine:

    queued -> awaiting_approval -> approved -> running -> complete
                     |                                        ^
                     +-------------- rejected                 |
                                                              +-- failed

Passive/static stages may begin while ``awaiting_approval``; active/dynamic stages are gated
by ``scope_guard.sh`` on ``authorised: true``, which only ``approve()`` sets. The GitHub
token never lands in the job dir — it lives in the secrets store as a ``token_ref``.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Optional

from .secrets_store import STORE

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JOBS_DIR = os.environ.get("BLACKWING_JOBS_DIR", os.path.join(_ROOT, "jobs"))

STATUSES = ("queued", "awaiting_approval", "approved", "running", "complete",
            "rejected", "failed")


@dataclass
class Targets:
    web_domain: str = ""
    source_repo_url: str = ""
    source_token_ref: str = ""
    android_apk_source: str = ""
    android_package_name: str = ""

    def active_tracks(self) -> list[str]:
        t = []
        if self.web_domain:
            t.append("web")
        if self.source_repo_url:
            t.append("source")
        if self.android_apk_source:
            t.append("android")
        return t


@dataclass
class Job:
    requester: str
    authority_reference: str
    targets: Targets = field(default_factory=Targets)
    terminal_recording: bool = False
    screen_recording: bool = False
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: str = "queued"
    authorised: bool = False
    approved_by: str = ""
    approved_at: str = ""
    created_at: float = field(default_factory=lambda: round(time.time(), 3))

    @property
    def dir(self) -> str:
        return os.path.join(JOBS_DIR, self.id)

    def to_public_dict(self) -> dict:
        """Serialisable view with no secrets (token_ref only, never the token)."""
        d = asdict(self)
        return d


class JobValidationError(ValueError):
    pass


def create_job(
    requester: str,
    authority_reference: str,
    *,
    web_domain: str = "",
    source_repo_url: str = "",
    github_token: str = "",
    android_apk_source: str = "",
    terminal_recording: bool = False,
    screen_recording: bool = False,
) -> Job:
    """Validate intake, register any token in the secrets store, create the job dir + scope."""
    requester = (requester or "").strip()
    authority_reference = (authority_reference or "").strip()
    if not requester:
        raise JobValidationError("requester identity is required (platform is not anonymous)")
    if not authority_reference:
        raise JobValidationError("authorisation reference is required — submission blocked")
    if not (web_domain or source_repo_url or android_apk_source):
        raise JobValidationError("at least one artifact (domain / repo / apk) must be provided")

    token_ref = ""
    if source_repo_url and github_token:
        token_ref = STORE.put(github_token, hint="github")

    job = Job(
        requester=requester,
        authority_reference=authority_reference,
        targets=Targets(
            web_domain=web_domain.strip(),
            source_repo_url=source_repo_url.strip(),
            source_token_ref=token_ref,
            android_apk_source=android_apk_source.strip(),
        ),
        terminal_recording=terminal_recording,
        screen_recording=screen_recording,
        status="awaiting_approval",
    )
    os.makedirs(job.dir, exist_ok=True)
    os.makedirs(os.path.join(job.dir, "artifacts"), exist_ok=True)
    os.makedirs(os.path.join(job.dir, "evidence", "video"), exist_ok=True)
    write_scope(job)
    _save_meta(job)
    return job


def write_scope(job: Job) -> str:
    """Render this job's scope.yaml from the template. Uses no YAML lib on the write side —
    the file is small and fixed-shape."""
    t = job.targets
    scope_path = os.path.join(job.dir, "scope.yaml")
    lines = [
        f'job_id: "{job.id}"',
        f'created_at: "{job.created_at}"',
        f'requester: "{job.requester}"',
        f'authorised: {"true" if job.authorised else "false"}',
        'authority:',
        f'  reference: "{job.authority_reference}"',
        f'  approved_by: "{job.approved_by}"',
        f'  approved_at: "{job.approved_at}"',
        'targets:',
        '  web:',
        f'    enabled: {"true" if t.web_domain else "false"}',
        f'    domain: "{t.web_domain}"',
        '    in_scope_hosts:' + ('' if t.web_domain else ' []'),
    ]
    if t.web_domain:
        lines.append(f'      - {t.web_domain}')
    lines += [
        '  source:',
        f'    enabled: {"true" if t.source_repo_url else "false"}',
        f'    repo_url: "{t.source_repo_url}"',
        f'    token_ref: "{t.source_token_ref}"',
        '  android:',
        f'    enabled: {"true" if t.android_apk_source else "false"}',
        f'    apk_source: "{t.android_apk_source}"',
        f'    package_name: "{t.android_package_name}"',
        'constraints:',
        '  detection_only: true',
        '  no_dorking: true',
        '  no_secret_use: true',
        '  embargo_until: ""',
        'evidence:',
        f'  terminal_recording: {"true" if job.terminal_recording else "false"}',
        f'  screen_recording: {"true" if job.screen_recording else "false"}',
    ]
    with open(scope_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return scope_path


def approve(job: Job, approver: str) -> Job:
    """Human-approval step: a reviewer (not the requester) authorises active/dynamic stages."""
    approver = (approver or "").strip()
    if not approver:
        raise JobValidationError("approver identity is required")
    if approver == job.requester:
        raise JobValidationError("approver must differ from requester (separation of duties)")
    job.authorised = True
    job.approved_by = approver
    job.approved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    job.status = "approved"
    write_scope(job)
    _save_meta(job)
    return job


def reject(job: Job, approver: str, reason: str = "") -> Job:
    job.status = "rejected"
    job.approved_by = (approver or "").strip()
    _save_meta(job, extra={"reject_reason": reason})
    return job


def set_status(job: Job, status: str) -> Job:
    if status not in STATUSES:
        raise JobValidationError(f"unknown status {status!r}")
    job.status = status
    _save_meta(job)
    return job


def _save_meta(job: Job, extra: Optional[dict] = None) -> None:
    meta = job.to_public_dict()
    if extra:
        meta.update(extra)
    path = os.path.join(job.dir, "job.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def load_job(job_id: str) -> Optional[Job]:
    path = os.path.join(JOBS_DIR, job_id, "job.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        d = json.load(fh)
    tgt = Targets(**d.pop("targets"))
    d.pop("dir", None)
    return Job(targets=tgt, **{k: v for k, v in d.items() if k in Job.__dataclass_fields__})


def list_jobs() -> list[dict]:
    out = []
    if not os.path.isdir(JOBS_DIR):
        return out
    for name in sorted(os.listdir(JOBS_DIR)):
        p = os.path.join(JOBS_DIR, name, "job.json")
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as fh:
                out.append(json.load(fh))
    out.sort(key=lambda j: j.get("created_at", 0), reverse=True)
    return out
