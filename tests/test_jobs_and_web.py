"""Tests for the simplified job intake and web routes (in-process TestClient)."""
import json
import os

import pytest


@pytest.fixture
def jobs_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKWING_JOBS_DIR", str(tmp_path / "jobs"))
    import importlib
    from orchestrator import jobs as jobs_mod
    importlib.reload(jobs_mod)
    return jobs_mod


def test_detect_track(jobs_env):
    j = jobs_env
    assert j.detect_track("https://github.com/org/repo") == "source"
    assert j.detect_track("https://cdn.example.com/app.apk") == "android"
    assert j.detect_track("https://example.com/login") == "web"


def test_create_from_url_web_autoauthorised(jobs_env):
    j = jobs_env.create_from_url("https://example.com")
    assert j.targets.web_domain == "https://example.com"
    assert j.authorised is True                       # operator is the authoriser
    assert "authorised: true" in open(os.path.join(j.dir, "scope.yaml")).read()


def test_create_from_url_source_with_token_not_persisted(jobs_env):
    j = jobs_env.create_from_url("https://github.com/acme/app",
                                 token="ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE12345")
    assert j.targets.source_repo_url.endswith("acme/app")
    assert j.targets.source_token_ref.startswith("secret://")
    assert "ghp_" not in open(os.path.join(j.dir, "scope.yaml")).read()


def test_web_token_stored_as_ref(jobs_env):
    j = jobs_env.create_from_url("https://example.com", token="sekrit-bearer-123")
    assert j.targets.web_token_ref.startswith("secret://")
    assert "sekrit-bearer" not in open(os.path.join(j.dir, "scope.yaml")).read()


def test_missing_url_rejected(jobs_env):
    with pytest.raises(jobs_env.JobValidationError):
        jobs_env.create_from_url("")


def test_web_routes_simple_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKWING_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("BLACKWING_MODEL_MOCK", "1")
    import importlib
    from orchestrator import jobs as jobs_mod
    importlib.reload(jobs_mod)
    from web.app import main as main_mod
    importlib.reload(main_mod)
    from fastapi.testclient import TestClient

    c = TestClient(main_mod.app, follow_redirects=False)
    r = c.get("/")
    assert r.status_code == 200 and "Start assessment" in r.text     # no login page
    r = c.post("/start", data={"url": "https://example.com"})
    assert r.status_code == 302 and r.headers["location"].startswith("/a/")
    jid = r.headers["location"].split("/")[-1]
    assert c.get(f"/a/{jid}").status_code == 200
    assert c.get(f"/a/{jid}/status.json").json().get("running") is not None
    assert c.post("/start", data={"url": ""}).status_code == 400     # friendly error


def test_evidence_download_and_traversal_guard(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKWING_JOBS_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("BLACKWING_MODEL_MOCK", "1")
    import importlib
    from orchestrator import jobs as jobs_mod
    importlib.reload(jobs_mod)
    from web.app import main as main_mod
    importlib.reload(main_mod)
    from fastapi.testclient import TestClient

    j = jobs_mod.create_from_url("https://example.com")
    vid = os.path.join(j.dir, "evidence", "video")
    os.makedirs(vid, exist_ok=True)
    open(os.path.join(vid, "terminal-1.log"), "w").write("session capture")

    c = TestClient(main_mod.app, follow_redirects=False)
    r = c.get(f"/a/{j.id}/evidence/video/terminal-1.log")
    assert r.status_code == 200 and "session capture" in r.text
    bad = c.get(f"/a/{j.id}/evidence/../../scope.yaml")
    assert bad.status_code in (400, 404)
