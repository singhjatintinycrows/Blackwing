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
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import deque


def _shquote(s: str) -> str:
    return shlex.quote(s)


def _evidence_flags(job_dir: str) -> tuple[bool, bool]:
    """Return (terminal_recording, screen_recording) from the job's scope.yaml."""
    try:
        if _ROOT not in sys.path:
            sys.path.insert(0, _ROOT)
        from lib import scope as scopelib
        sc = scopelib.load(os.path.join(job_dir, "scope.yaml"))
        ev = sc.raw.get("evidence", {})
        return bool(ev.get("terminal_recording")), bool(ev.get("screen_recording"))
    except Exception:
        return False, False
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
            mode = os.environ.get("BLACKWING_ENGINE_MODE", "codex")
            if self.use_sandbox and shutil.which("docker"):
                cmd = ["bash", os.path.join(_ROOT, "sandbox", "run_sandbox.sh"), job_dir]
                env = dict(os.environ)
            elif mode in ("codex", "agent", "opencode"):
                # A headless coding agent (OpenCode by default, or Codex) IS the engine: it runs
                # the whole assessment itself and reports the findings.
                cmd = [sys.executable, "-m", "bin.agent_runner", job_dir]
                env = dict(os.environ, BLACKWING_ENGINE="1",
                           BLACKWING_JOBS_DIR=self.jobs_dir,
                           PYTHONPATH=_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
            else:
                # Legacy built-in Python detector engine (BLACKWING_ENGINE_MODE=python).
                cmd = [sys.executable, "-m", "bin.run_job", job_dir]
                env = dict(os.environ, BLACKWING_ENGINE="1",
                           BLACKWING_JOBS_DIR=self.jobs_dir,
                           PYTHONPATH=_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
                if self.mock:
                    env["BLACKWING_MODEL_MOCK"] = "1"
            cmd = self._wrap_evidence(job_dir, cmd)
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

    def _wrap_evidence(self, job_dir: str, cmd: list) -> list:
        """Wrap the engine command to capture evidence when the job's scope requests it.

        Terminal/session recording uses util-linux ``script`` (a real .cast-style typescript).
        Screen recording needs a display, which the headless engine lacks; we drop a note so
        the artifact slot exists and is populated by the dynamic/browser stages when a display
        (Xvfb + ffmpeg) is available. Both land under evidence/video/ and are downloadable.
        """
        vid = os.path.join(job_dir, "evidence", "video")
        os.makedirs(vid, exist_ok=True)
        term, screen = _evidence_flags(job_dir)
        if screen:
            note = os.path.join(vid, "screen-recording.README.txt")
            if not os.path.exists(note):
                with open(note, "w", encoding="utf-8") as fh:
                    fh.write("Screen recording requires a display. Dynamic/browser stages "
                             "capture screen.mp4 here via Xvfb+ffmpeg when a display is present.\n")
        if term and shutil.which("script"):
            ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            out = os.path.join(vid, f"terminal-{ts}.log")
            inner = " ".join(_shquote(c) for c in cmd)
            return ["script", "-q", "-c", inner, out]
        return cmd


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
