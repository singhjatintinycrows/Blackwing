"""Tests for the durable job queue and submission rate-limiter."""
import os
import time

from orchestrator.queue import JobQueue, RateLimiter


def test_rate_limiter_blocks_flood():
    rl = RateLimiter(limit=3, window=60)
    k = "alice@x.com"
    assert [rl.allow(k) for _ in range(3)] == [True, True, True]
    assert rl.allow(k) is False              # 4th within window blocked
    assert rl.retry_after(k) > 0
    # a different key is independent
    assert rl.allow("bob@x.com") is True


def test_rate_limiter_window_resets():
    rl = RateLimiter(limit=1, window=0.3)
    assert rl.allow("k") is True
    assert rl.allow("k") is False
    time.sleep(0.35)
    assert rl.allow("k") is True


def test_queue_runs_job(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKWING_MODEL_MOCK", "1")
    jobs_dir = tmp_path / "jobs"
    job_id = "job123"
    jd = jobs_dir / job_id
    (jd / "artifacts" / "repo" / "app").mkdir(parents=True)
    (jd / "artifacts" / "repo" / "app" / "v.py").write_text(
        "name = request.args.get('n')\nimport os\nos.system('ping ' + name)\n")
    (jd / "scope.yaml").write_text(
        'job_id: "job123"\nauthorised: true\nauthority:\n  reference: "S"\n'
        'targets:\n  source:\n    enabled: true\n    repo_url: "local"\n    token_ref: ""\n')

    q = JobQueue(jobs_dir=str(jobs_dir), max_concurrency=1, mock=True)
    q.enqueue(job_id)
    # wait for the worker to finish
    for _ in range(100):
        if not q.is_active(job_id) and (jd / "findings.json").exists():
            break
        time.sleep(0.2)
    assert (jd / "findings.json").exists()
    import json
    findings = json.loads((jd / "findings.json").read_text())
    assert any(f["cls"] == "command-injection" for f in findings)


def test_queue_persistence(tmp_path):
    jobs_dir = tmp_path / "jobs"
    jobs_dir.mkdir()
    q = JobQueue(jobs_dir=str(jobs_dir), max_concurrency=0)  # 0 -> nothing runs, stays pending
    # max_concurrency 0 means the semaphore never grants; enqueue persists to disk
    q._pending.append("pendingjob")
    q._persist()
    assert os.path.exists(os.path.join(str(jobs_dir), "_queue.json"))
    q2 = JobQueue(jobs_dir=str(jobs_dir), max_concurrency=0)
    q2.load_persisted()
    assert "pendingjob" in q2.status()["pending"]
