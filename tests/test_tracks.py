"""Tests for taint scanning, android triage, and the source track end-to-end (mock model)."""
import json
import os

from lib import android_triage, taint


def test_taint_finds_sqli_and_cmdi(tmp_path):
    f = tmp_path / "v.py"
    f.write_text(
        "name = request.args.get('n')\n"
        "import os\n"
        "os.system('echo ' + name)\n"
        "cur.execute('SELECT * FROM t WHERE x = %s' % name)\n"
    )
    hits = taint.scan_file(str(f))
    classes = {h.cls for h in hits}
    assert "command-injection" in classes
    assert "sqli" in classes
    assert any(h.has_nearby_source for h in hits)


def test_taint_sanitiser_lowers_confidence(tmp_path):
    f = tmp_path / "s.py"
    f.write_text(
        "import shlex, os\n"
        "name = request.args.get('n')\n"
        "os.system('echo ' + shlex.quote(name))\n"
    )
    hits = [h for h in taint.scan_file(str(f)) if h.cls == "command-injection"]
    assert hits and hits[0].has_nearby_sanitiser


def _manifest(tmp_path):
    p = tmp_path / "AndroidManifest.xml"
    p.write_text(
        '<?xml version="1.0"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.x" android:versionCode="7" android:versionName="1.0">'
        '<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>'
        '<application android:debuggable="true" android:allowBackup="true">'
        '<activity android:name=".Exp" android:exported="true"/>'
        '<activity android:name=".Deep" android:exported="true">'
        '<intent-filter android:autoVerify="true"><data android:scheme="https"/></intent-filter></activity>'
        '<provider android:name=".P" android:exported="true"/>'
        '</application></manifest>'
    )
    return str(p)


def test_android_manifest_parse_and_triage(tmp_path):
    summ = android_triage.parse_manifest(_manifest(tmp_path))
    assert summ.package == "com.x"
    assert summ.target_sdk == "33"
    assert summ.debuggable is True
    cls = [c["cls"] for c in android_triage.triage(summ)]
    # exported-no-permission must be prioritised first
    assert cls[0] == "exported-no-permission"
    assert "app-link" in cls
    assert "content-provider" in cls


def test_source_track_end_to_end(tmp_path, monkeypatch):
    # Build a job dir with a scope + a vulnerable repo, run the source track with the mock model.
    monkeypatch.setenv("BLACKWING_ENGINE", "1")
    monkeypatch.setenv("BLACKWING_MODEL_MOCK", "1")
    job = tmp_path / "job1"
    (job / "artifacts" / "repo" / "app").mkdir(parents=True)
    (job / "artifacts" / "repo" / "app" / "v.py").write_text(
        "name = request.args.get('n')\nimport os\nos.system('ping ' + name)\n"
    )
    (job / "scope.yaml").write_text(
        'job_id: "job1"\nauthorised: true\nauthority:\n  reference: "SOW-1"\n'
        'targets:\n  source:\n    enabled: true\n    repo_url: "local"\n    token_ref: ""\n'
    )
    from bin import run_job
    summary = run_job.run(str(job), mock=True)
    assert "source" in summary["tracks"]
    findings = json.loads((job / "findings.json").read_text())
    assert any(f["cls"] == "command-injection" for f in findings)
    assert (job / "report.md").exists()
    # audit chain intact
    assert summary["audit_intact"] is True
