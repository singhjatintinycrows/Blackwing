"""Launch the engine for a job in an isolated subprocess.

Each run executes ``python -m bin.run_job <job_dir>`` with ``BLACKWING_ENGINE=1`` so the
control-plane hooks fail-closed, in its own process so the engine's per-stage environment
never bleeds between jobs (a step toward the per-job sandbox of issue #6). The web layer only
reads job artifacts back; it never runs pentest logic in-process.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_running: dict[str, bool] = {}
_lock = threading.Lock()


def is_running(job_id: str) -> bool:
    with _lock:
        return _running.get(job_id, False)


def launch(job_dir: str, mock: bool | None = None) -> None:
    job_id = os.path.basename(job_dir.rstrip("/"))
    with _lock:
        if _running.get(job_id):
            return
        _running[job_id] = True

    def _worker():
        env = dict(os.environ)
        env["BLACKWING_ENGINE"] = "1"
        env["BLACKWING_JOBS_DIR"] = os.path.dirname(job_dir.rstrip("/"))
        env["PYTHONPATH"] = _ROOT + os.pathsep + env.get("PYTHONPATH", "")
        if mock or os.environ.get("BLACKWING_MODEL_MOCK") == "1":
            env["BLACKWING_MODEL_MOCK"] = "1"
        cmd = [sys.executable, "-m", "bin.run_job", job_dir]
        log = os.path.join(job_dir, "engine.log")
        try:
            with open(log, "a", encoding="utf-8") as fh:
                subprocess.run(cmd, cwd=_ROOT, env=env, stdout=fh, stderr=fh, timeout=1800)
        finally:
            with _lock:
                _running[job_id] = False

    threading.Thread(target=_worker, daemon=True).start()
