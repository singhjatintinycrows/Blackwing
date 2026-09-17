"""End-to-end test of the web track's detection-only specialists against a local vuln server."""
import http.server
import re
import socketserver
import threading
import urllib.parse

import pytest


class _Vuln(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        if u.path == "/":
            self._send('<a href="/search?q=hi">s</a><a href="/tmpl?name=x">t</a><a href="/item?id=1">i</a>')
        elif u.path == "/search":
            self._send(f"Results for: {q.get('q','')}")            # reflected XSS
        elif u.path == "/tmpl":
            r = re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
                       lambda m: str(int(m.group(1)) * int(m.group(2))), q.get("name", ""))
            self._send(f"Hello {r}")                                # SSTI
        elif u.path == "/item":
            self._send("no item found" if "'1'='2" in q.get("id", "")
                       else "Item #1 Widget price 9.99 in stock sku ABC123")  # boolean SQLi
        else:
            self._send("404", 404)


@pytest.fixture
def vuln_server():
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Vuln)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


def test_web_specialists_detect_and_confirm(tmp_path, monkeypatch, vuln_server):
    monkeypatch.setenv("BLACKWING_ENGINE", "1")
    monkeypatch.setenv("BLACKWING_MODEL_MOCK", "1")
    monkeypatch.setenv("BLACKWING_JOBS_DIR", str(tmp_path / "jobs"))
    import importlib
    from orchestrator import jobs as jobs_mod
    importlib.reload(jobs_mod)

    j = jobs_mod.create_job(requester="a@x.com", authority_reference="SOW-1",
                            web_domain=f"127.0.0.1:{vuln_server}")
    jobs_mod.approve(j, "reviewer@x.com")

    from bin import run_job
    summary = run_job.run(j.dir, mock=True)
    assert "web" in summary["tracks"]
    import json
    findings = json.loads(open(j.dir + "/findings.json").read())
    confirmed = {(f["cls"]) for f in findings if f["status"] == "confirmed"}
    assert "xss" in confirmed
    assert "sqli" in confirmed
    assert "ssti" in confirmed


def test_web_client_enforces_scope():
    from lib import webprobe
    cli = webprobe.HttpClient(in_scope_hosts=["example.com"])
    with pytest.raises(webprobe.ScopeViolation):
        cli.get("http://evil.com/")
    assert webprobe.host_in_scope("api.example.com", ["example.com"])
    assert not webprobe.host_in_scope("evil.com", ["example.com"])


def test_web_active_stages_gated_when_unapproved(tmp_path, monkeypatch, vuln_server):
    monkeypatch.setenv("BLACKWING_ENGINE", "1")
    monkeypatch.setenv("BLACKWING_MODEL_MOCK", "1")
    monkeypatch.setenv("BLACKWING_JOBS_DIR", str(tmp_path / "jobs"))
    import importlib
    from orchestrator import jobs as jobs_mod
    importlib.reload(jobs_mod)
    j = jobs_mod.create_job(requester="a@x.com", authority_reference="SOW-1",
                            web_domain=f"127.0.0.1:{vuln_server}")
    # not approved
    from bin import run_job
    summary = run_job.run(j.dir, mock=True)
    skipped = {s["stage"] for s in summary["stages"] if s["status"] == "skipped"}
    assert {"02-active-web", "xss", "sqli", "ssti", "10-validation"} <= skipped
