"""Durable job queue + submission rate-limiting (issue #5).

The web layer never runs pentest logic in-process; it *enqueues* a job. A bounded worker pool
processes the queue with a concurrency cap, running each job in its own subprocess (or the
per-job Docker sandbox when available), so one engagement can never see another's data.

Durable: the pending list is persisted to ``jobs/_queue.json`` and re-loaded on startup, so a
restart resumes queued work instead of losing it. Rate-limiting is a per-requester sliding
window that blocks submission floods.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- rate limiting
class RateLimiter:
    """Per-key sliding-window limiter: at most ``limit`` events per ``window`` seconds."""

    def __init__(self, limit: int = 5, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._events: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            dq = self._events.setdefault(key, deque())
            while dq and now - dq[0] > self.window:
                dq.popleft()
            if len(dq) >= self.limit:
                return False
            dq.append(now)
            return True

    def retry_after(self, key: str) -> float:
        with self._lock:
            dq = self._events.get(key)
            if not dq:
                return 0.0
            return max(0.0, self.window - (time.time() - dq[0]))


# --------------------------------------------------------------------------- job queue
@dataclass
class JobQueue:
    jobs_dir: str
    max_concurrency: int = 2
    use_sandbox: bool = False
    mock: bool = False
    _pending: deque = field(default_factory=deque)
    _running: set = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _sem: Optional[threading.Semaphore] = None
    _started: bool = False

    def __post_init__(self):
        self._sem = threading.Semaphore(self.max_concurrency)
        self._queue_file = os.path.join(self.jobs_dir, "_queue.json")

    # -- persistence --------------------------------------------------------
    def _persist(self):
        os.makedirs(self.jobs_dir, exist_ok=True)
        tmp = self._queue_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"pending": list(self._pending), "running": list(self._running)}, fh)
        os.replace(tmp, self._queue_file)

    def load_persisted(self):
        if os.path.exists(self._queue_file):
            with open(self._queue_file, encoding="utf-8") as fh:
                data = json.load(fh)
            with self._lock:
                # anything that was pending or mid-run when we stopped goes back to pending
                for jid in data.get("pending", []) + data.get("running", []):
                    if jid not in self._pending:
                        self._pending.append(jid)
            self._persist()

    # -- api ----------------------------------------------------------------
    def enqueue(self, job_id: str) -> None:
        with self._lock:
            if job_id not in self._pending and job_id not in self._running:
                self._pending.append(job_id)
                self._persist()
        self._pump()

    def status(self) -> dict:
        with self._lock:
            return {"pending": list(self._pending), "running": list(self._running),
                    "capacity": self.max_concurrency}

    def is_active(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._pending or job_id in self._running

    # -- worker pump --------------------------------------------------------
    def _pump(self):
        while True:
            if not self._sem.acquire(blocking=False):
                return
            with self._lock:
                if not self._pending:
                    self._sem.release()
                    return
                job_id = self._pending.popleft()
                self._running.add(job_id)
                self._persist()
            threading.Thread(target=self._run, args=(job_id,), daemon=True).start()

    def _run(self, job_id: str):
        job_dir = os.path.join(self.jobs_dir, job_id)
        try:
            if self.use_sandbox and shutil.which("docker"):
                cmd = ["bash", os.path.join(_ROOT, "sandbox", "run_sandbox.sh"), job_dir]
                env = dict(os.environ)
            else:
                cmd = [sys.executable, "-m", "bin.run_job", job_dir]
                env = dict(os.environ, BLACKWING_ENGINE="1",
                           BLACKWING_JOBS_DIR=self.jobs_dir,
                           PYTHONPATH=_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
                if self.mock:
                    env["BLACKWING_MODEL_MOCK"] = "1"
            log = os.path.join(job_dir, "engine.log")
            with open(log, "a", encoding="utf-8") as fh:
                subprocess.run(cmd, cwd=_ROOT, env=env, stdout=fh, stderr=fh, timeout=3600)
        except Exception as e:  # noqa: BLE001 — record and move on; one job never blocks others
            try:
                with open(os.path.join(job_dir, "engine.log"), "a", encoding="utf-8") as fh:
                    fh.write(f"[queue] run failed: {e}\n")
            except OSError:
                pass
        finally:
            with self._lock:
                self._running.discard(job_id)
                self._persist()
            self._sem.release()
            self._pump()


# Process-wide default instances, sized from env.
_default_queue: Optional[JobQueue] = None


def get_queue() -> JobQueue:
    global _default_queue
    if _default_queue is None:
        jobs_dir = os.environ.get("BLACKWING_JOBS_DIR", os.path.join(_ROOT, "jobs"))
        _default_queue = JobQueue(
            jobs_dir=jobs_dir,
            max_concurrency=int(os.environ.get("BLACKWING_MAX_CONCURRENCY", "2")),
            use_sandbox=os.environ.get("BLACKWING_USE_SANDBOX", "0") == "1",
            mock=os.environ.get("BLACKWING_MODEL_MOCK", "0") == "1",
        )
        _default_queue.load_persisted()
    return _default_queue


_default_limiter: Optional[RateLimiter] = None


def get_limiter() -> RateLimiter:
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = RateLimiter(
            limit=int(os.environ.get("BLACKWING_RATE_LIMIT", "5")),
            window=float(os.environ.get("BLACKWING_RATE_WINDOW", "60")),
        )
    return _default_limiter
