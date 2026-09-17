"""Detection-only web probing primitives for Track A.

stdlib-only HTTP with **in-engine scope enforcement** (defence in depth alongside
scope_guard.sh) and **control-contrast** detectors. Every detector observes a discriminating
response differential — it never extracts data, escalates, or causes real impact:

* reflected XSS — does an injected marker survive into HTML *unencoded* (vs a safe control)?
* SSTI          — do two different arithmetic expressions each evaluate to their product?
* boolean SQLi  — does a TRUE condition match the baseline while a FALSE condition diverges?
* error SQLi    — does a single quote surface a database error signature?

These produce candidates; `lib/validation.n_of_m_contrast` confirms them by repetition + a
negative control before anything is reported as confirmed.
"""
from __future__ import annotations

import difflib
import random
import re
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

USER_AGENT = "Blackwing/1.0 (authorised-only; detection-only)"


class ScopeViolation(Exception):
    pass


def host_in_scope(host: str, allowlist: list[str]) -> bool:
    host = (host or "").lower().split(":")[0]
    for a in allowlist:
        a = a.lower().split("//")[-1].split("/")[0].split(":")[0]  # strip scheme/path/port
        if host == a or host.endswith("." + a):
            return True
    return False


@dataclass
class Response:
    status: int
    headers: dict
    body: str
    elapsed: float
    url: str


@dataclass
class HttpClient:
    in_scope_hosts: list[str]
    timeout: float = 10.0
    extra_headers: dict = field(default_factory=dict)
    request_count: int = 0
    max_requests: int = 2000

    def _check(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ScopeViolation(f"unsupported scheme: {parsed.scheme}")
        if not host_in_scope(parsed.hostname or "", self.in_scope_hosts):
            raise ScopeViolation(f"host {parsed.hostname!r} not in scope {self.in_scope_hosts}")

    def get(self, url: str, headers: Optional[dict] = None) -> Response:
        self._check(url)
        if self.request_count >= self.max_requests:
            raise ScopeViolation("request budget exhausted")
        self.request_count += 1
        h = {"User-Agent": USER_AGENT, **self.extra_headers, **(headers or {})}
        req = urllib.request.Request(url, headers=h, method="GET")
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(2_000_000).decode("utf-8", "replace")
                return Response(resp.status, dict(resp.headers), body, time.time() - t0, url)
        except urllib.error.HTTPError as e:
            body = e.read(500_000).decode("utf-8", "replace") if e.fp else ""
            return Response(e.code, dict(e.headers or {}), body, time.time() - t0, url)


# -- URL/param helpers -------------------------------------------------------
def with_param(url: str, name: str, value: str) -> str:
    parts = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    q[name] = value
    return urllib.parse.urlunparse(parts._replace(query=urllib.parse.urlencode(q)))


def params_of(url: str) -> list[str]:
    return [k for k, _ in urllib.parse.parse_qsl(urllib.parse.urlparse(url).query, keep_blank_values=True)]


_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.I)


def extract_links(base_url: str, body: str) -> list[str]:
    out = []
    for m in _LINK_RE.findall(body):
        try:
            out.append(urllib.parse.urljoin(base_url, m))
        except ValueError:
            continue
    return out


def _rand(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def similarity(a: str, b: str) -> float:
    """Ratio 0..1 of how similar two response bodies are (length-capped for speed)."""
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()


# -- detectors (each returns (is_candidate, detail, evidence_dict)) -----------
def detect_reflected_xss(client: HttpClient, url: str, param: str) -> tuple[bool, str, dict]:
    marker = "bwx" + _rand(6)
    payload = f"{marker}<b>{marker}</b>"            # angle brackets are the discriminator
    safe = f"{marker}SAFE{marker}"                   # control: reflects, but nothing to encode
    r_payload = client.get(with_param(url, param, payload))
    r_safe = client.get(with_param(url, param, safe))
    raw_reflected = f"<b>{marker}</b>" in r_payload.body
    control_ok = marker in r_safe.body and f"<b>{marker}</b>" not in r_safe.body
    is_cand = raw_reflected and control_ok
    return is_cand, ("angle brackets reflected unencoded" if is_cand else "no raw reflection"), {
        "param": param, "marker": marker, "status": r_payload.status}


def detect_ssti(client: HttpClient, url: str, param: str) -> tuple[bool, str, dict]:
    m = _rand(4)
    # two distinct expressions -> their products; both must evaluate for a confirmed contrast
    r49 = client.get(with_param(url, param, f"{m}{{{{7*7}}}}{m}"))
    r64 = client.get(with_param(url, param, f"{m}{{{{8*8}}}}{m}"))
    hit49 = f"{m}49{m}" in r49.body
    hit64 = f"{m}64{m}" in r64.body
    is_cand = hit49 and hit64
    return is_cand, ("template engine evaluated 7*7 and 8*8" if is_cand else "no evaluation"), {
        "param": param, "evaluated": is_cand}


def detect_boolean_sqli(client: HttpClient, url: str, param: str, baseline: str = "1") -> tuple[bool, str, dict]:
    r_base = client.get(with_param(url, param, baseline))
    r_true = client.get(with_param(url, param, f"{baseline}' AND '1'='1"))
    r_false = client.get(with_param(url, param, f"{baseline}' AND '1'='2"))
    sim_true = similarity(r_base.body, r_true.body)
    sim_false = similarity(r_base.body, r_false.body)
    # TRUE tracks baseline, FALSE diverges -> boolean-based injection signal
    is_cand = sim_true > 0.95 and sim_false < 0.9 and (sim_true - sim_false) > 0.1
    return is_cand, f"true~baseline={sim_true:.2f} false~baseline={sim_false:.2f}", {
        "param": param, "sim_true": round(sim_true, 3), "sim_false": round(sim_false, 3)}


_SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"you have an error in your sql)", re.I)


def detect_error_sqli(client: HttpClient, url: str, param: str) -> tuple[bool, str, dict]:
    r = client.get(with_param(url, param, "1'"))
    m = _SQL_ERRORS.search(r.body)
    return bool(m), (f"db error signature: {m.group(0)!r}" if m else "no error signature"), {
        "param": param, "status": r.status}


def detect_idor(client: HttpClient, url: str, param: str,
                auth_headers: Optional[dict] = None) -> tuple[bool, str, dict]:
    """Access-control differential: does an object reference return content the same whether or
    not credentials are supplied? Detection-only — we compare a benign object id, we do not
    harvest data. Requires numeric-ish id params."""
    r_auth = client.get(with_param(url, param, "1"), headers=auth_headers or {})
    r_anon = client.get(with_param(url, param, "1"), headers={"Cookie": "", "Authorization": ""})
    # If anon gets a 200 with substantive, near-identical content to auth, the object is
    # unprotected. Only a signal when auth_headers were actually provided.
    if not auth_headers:
        return False, "no credentials supplied to contrast against", {"param": param}
    is_cand = r_anon.status == 200 and similarity(r_auth.body, r_anon.body) > 0.9 and len(r_anon.body) > 50
    return is_cand, f"anon status={r_anon.status} sim={similarity(r_auth.body, r_anon.body):.2f}", {
        "param": param, "anon_status": r_anon.status}
