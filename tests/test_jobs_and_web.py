"""Tests for the job lifecycle and the web routes (in-process TestClient)."""
import json
import os

import pytest


@pytest.fixture
def jobs_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKWING_JOBS_DIR", str(tmp_path / "jobs"))
    # reimport jobs so JOBS_DIR picks up the env
    import importlib
    from orchestrator import jobs as jobs_mod
    importlib.reload(jobs_mod)
    return jobs_mod


def test_job_creation_and_scope(jobs_env):
    jobs_mod = jobs_env
    j = jobs_mod.create_job(
        requester="alice@x.com", authority_reference="SOW-1",
        web_domain="acme.example.com",
        source_repo_url="https://github.com/acme/app",
        github_token="ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE12345",
    )
    scope_text = open(os.path.join(j.dir, "scope.yaml")).read()
    assert "ghp_" not in scope_text          # token never persisted
    assert j.targets.source_token_ref.startswith("secret://")
    assert j.status == "awaiting_approval"


def test_authority_reference_required(jobs_env):
    jobs_mod = jobs_env
    with pytest.raises(jobs_mod.JobValidationError):
        jobs_mod.create_job(requester="a", authority_reference="", web_domain="x.com")


def test_approval_separation_of_duties(jobs_env):
    jobs_mod = jobs_env
    j = jobs_mod.create_job(requester="alice@x.com", authority_reference="SOW-1", web_domain="x.com")
    with pytest.raises(jobs_mod.JobValidationError):
        jobs_mod.approve(j, "alice@x.com")          # requester cannot approve
    jobs_mod.approve(j, "reviewer@x.com")
    assert j.authorised is True and j.approved_by == "reviewer@x.com"


def test_web_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKWING_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("BLACKWING_MODEL_MOCK", "1")
    monkeypatch.setenv("BLACKWING_REVIEWERS", "reviewer@x.com")
    monkeypatch.setenv("BLACKWING_SECRET_KEY", "test")
    import importlib
    from orchestrator import jobs as jobs_mod
    importlib.reload(jobs_mod)
    from web.app import auth as auth_mod
    importlib.reload(auth_mod)
    from web.app import main as main_mod
    importlib.reload(main_mod)
    from fastapi.testclient import TestClient

    c = TestClient(main_mod.app, follow_redirects=False)
    assert c.get("/login").status_code == 200
    assert c.get("/dashboard").status_code == 302             # anon redirected
    c.post("/login", data={"identity": "alice@x.com"})
    r = c.post("/submit", data={"authority_reference": "SOW-1",
                                "source_repo_url": "https://github.com/octocat/Hello-World"})
    assert r.status_code == 302
    jid = r.headers["location"].split("/")[-1]
    assert c.get(f"/jobs/{jid}").status_code == 200
    assert c.post(f"/jobs/{jid}/approve").status_code == 403   # alice not a reviewer
    c.post("/login", data={"identity": "reviewer@x.com"})
    assert c.post(f"/jobs/{jid}/approve").status_code == 302   # reviewer ok
