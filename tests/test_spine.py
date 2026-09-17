"""Tests for the non-negotiable spine: redaction, audit chain, scope gate, validation."""
import os
import textwrap

from lib import audit, redact, scope as scopelib, validation


def test_redact_known_secret_kinds():
    s = ("gh ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE12345 "
         "aws ABSKEXAMPLEEXAMPLEEXAMPLEEXAMPLEabcd12 "
         "jwt eyJhbGciOi.eyJzdWIiOi.sig123456789")
    out = redact.redact(s)
    assert "ghp_EXAMPLE" not in out
    assert "ABSKEXAMPLEEXAMPLE" not in out
    kinds = redact.contains_secret(s)
    assert "github_pat" in kinds and "aws_bedrock_bearer" in kinds


def test_registered_secret_redaction():
    redact.register_extra_secrets(["S3cretValue123"])
    assert "S3cretValue123" not in redact.redact("token=S3cretValue123 here")


def test_audit_chain_verifies_and_detects_tamper(tmp_path):
    log = audit.AuditLog(str(tmp_path / "audit.jsonl"))
    log.append("a", {"x": 1})
    log.append("b", {"y": 2})
    log.append("c", {"z": 3})
    ok, idx = log.verify()
    assert ok and idx is None

    # Tamper with the middle line.
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    lines[1] = lines[1].replace('"y":2', '"y":9') if '"y":2' in lines[1] else lines[1].replace("2", "9", 1)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    ok2, idx2 = log.verify()
    assert not ok2 and idx2 is not None


def test_audit_redacts_secrets(tmp_path):
    log = audit.AuditLog(str(tmp_path / "a.jsonl"))
    log.append("tool", {"cmd": "curl -H 'Authorization: Bearer ghp_EXAMPLEEXAMPLEEXAMPLEEXAMPLE12345'"})
    assert "ghp_" not in (tmp_path / "a.jsonl").read_text()


def _scope(tmp_path, authorised=False, ref="SOW-1"):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(f"""
        job_id: J
        authorised: {'true' if authorised else 'false'}
        authority:
          reference: "{ref}"
        targets:
          web:
            in_scope_hosts:
              - example.com
              - api.example.com
    """))
    return scopelib.load(str(p))


def test_scope_passive_allowed_active_gated(tmp_path):
    sc = _scope(tmp_path, authorised=False)
    assert sc.allows_stage("source-orient")[0] is True
    assert sc.allows_stage("02-active-web")[0] is False
    assert sc.in_scope_hosts == ["example.com", "api.example.com"]


def test_scope_active_allowed_after_approval(tmp_path):
    sc = _scope(tmp_path, authorised=True)
    assert sc.allows_stage("02-active-web")[0] is True


def test_scope_active_denied_without_authority(tmp_path):
    sc = _scope(tmp_path, authorised=True, ref="")
    assert sc.allows_stage("02-active-web")[0] is False


def test_scope_unknown_stage_fails_closed(tmp_path):
    sc = _scope(tmp_path, authorised=True)
    assert sc.allows_stage("mystery")[0] is False


def test_n_of_m_contrast():
    good = validation.n_of_m_contrast(lambda: True, lambda: False, m=5, n=3)
    assert good.confirmed
    # negative control firing means the probe is non-discriminating -> not confirmed
    bad = validation.n_of_m_contrast(lambda: True, lambda: True, m=5, n=3)
    assert not bad.confirmed


def test_ledger_keeps_refuted():
    led = validation.Ledger()
    led.record(validation.Candidate("h1", "source").confirm())
    led.record(validation.Candidate("h2", "source").refute())
    assert len(led.confirmed()) == 1
    assert len(led.refuted()) == 1
    assert len(led.all()) == 2
