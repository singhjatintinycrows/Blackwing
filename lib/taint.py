"""Source-review taint model: sources, sinks, sanitisers, reachability.

Track B's reasoning core. It does not try to be a full interprocedural dataflow engine —
that belongs to dedicated SAST (Semgrep/CodeQL) which the track can shell out to. What this
provides is the *trust model* and a lightweight regex/grep candidate finder that seeds the
`source-tracer` agent's ledger, plus the priority ordering the methodology mandates.

stdlib-only. Language-aware sink/source tables keyed by a coarse language id.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable

# Dangerous sinks by language -> class. Coarse but high-signal; the agent confirms reachability.
SINKS: dict[str, dict[str, list[str]]] = {
    "python": {
        "command-injection": [r"\bos\.system\(", r"\bsubprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True", r"\bos\.popen\("],
        "sqli": [r"\.execute\(\s*[f'\"].*%|\.execute\(\s*.*\+", r"\.raw\(", r"cursor\.execute\([^,]*%"],
        "ssti": [r"render_template_string\(", r"Template\([^)]*\)\.render\("],
        "path-traversal": [r"open\(\s*.*\+", r"send_file\(", r"os\.path\.join\([^)]*request"],
        "deserialization": [r"pickle\.loads?\(", r"yaml\.load\((?!.*Loader)", r"marshal\.loads\("],
        "ssrf": [r"requests\.(?:get|post)\(", r"urllib\.request\.urlopen\("],
    },
    "javascript": {
        "command-injection": [r"child_process\.(?:exec|execSync)\(", r"\.exec\("],
        "sqli": [r"\.query\(\s*[`'\"].*\$\{", r"\.query\(\s*.*\+"],
        "xss": [r"\.innerHTML\s*=", r"dangerouslySetInnerHTML", r"document\.write\("],
        "path-traversal": [r"fs\.readFile(?:Sync)?\(", r"res\.sendFile\("],
        "deserialization": [r"JSON\.parse\(", r"eval\(", r"Function\("],
        "ssrf": [r"axios\.(?:get|post)\(", r"fetch\(", r"http\.request\("],
    },
    "java": {
        "sqli": [r"createStatement\(\)", r"Statement.*executeQuery\(\s*\".*\+"],
        "command-injection": [r"Runtime\.getRuntime\(\)\.exec\(", r"ProcessBuilder\("],
        "path-traversal": [r"new\s+File\(", r"Files\.(?:read|newInputStream)\("],
        "deserialization": [r"ObjectInputStream", r"readObject\("],
        "xxe": [r"DocumentBuilderFactory", r"SAXParserFactory", r"XMLInputFactory"],
        "ssrf": [r"new\s+URL\(", r"HttpURLConnection", r"HttpClient"],
    },
}

# Untrusted sources (request-derived) by language.
SOURCES: dict[str, list[str]] = {
    "python": [r"request\.(?:args|form|json|values|data|files|cookies|headers)", r"sys\.argv", r"os\.environ"],
    "javascript": [r"req\.(?:query|body|params|headers|cookies)", r"process\.argv", r"location\.(?:search|hash|href)"],
    "java": [r"getParameter\(", r"getHeader\(", r"getInputStream\(", r"@RequestParam", r"@PathVariable"],
}

# Sanitiser hints — presence near a sink lowers (not eliminates) confidence.
SANITISERS: dict[str, list[str]] = {
    "python": [r"shlex\.quote", r"escape\(", r"parameterized", r"\?\s*,", r"bleach\.", r"secure_filename"],
    "javascript": [r"escape\(", r"encodeURI", r"parameterized", r"\?\?", r"DOMPurify", r"validator\."],
    "java": [r"PreparedStatement", r"ESAPI", r"encodeFor", r"Pattern\.matches"],
}

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".mjs": "javascript", ".java": "java",
}


@dataclass
class SinkHit:
    path: str
    line: int
    language: str
    cls: str
    snippet: str
    has_nearby_source: bool = False
    has_nearby_sanitiser: bool = False
    confidence: str = "tentative"
    context: list[str] = field(default_factory=list)


def _lang_for(path: str) -> str | None:
    return EXT_LANG.get(os.path.splitext(path)[1].lower())


def scan_file(path: str, window: int = 6) -> list[SinkHit]:
    lang = _lang_for(path)
    if not lang:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    hits: list[SinkHit] = []
    src_pats = [re.compile(p) for p in SOURCES.get(lang, [])]
    san_pats = [re.compile(p) for p in SANITISERS.get(lang, [])]
    for cls, pats in SINKS.get(lang, {}).items():
        for pat in map(re.compile, pats):
            for i, line in enumerate(lines):
                if pat.search(line):
                    lo, hi = max(0, i - window), min(len(lines), i + window + 1)
                    ctx = lines[lo:hi]
                    ctx_text = "".join(ctx)
                    near_src = any(p.search(ctx_text) for p in src_pats)
                    near_san = any(p.search(ctx_text) for p in san_pats)
                    conf = "firm" if near_src and not near_san else (
                        "tentative" if near_src else "tentative")
                    hits.append(SinkHit(
                        path=path, line=i + 1, language=lang, cls=cls,
                        snippet=line.strip()[:200], has_nearby_source=near_src,
                        has_nearby_sanitiser=near_san, confidence=conf,
                        context=[c.rstrip() for c in ctx],
                    ))
    return hits


SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv"}


def scan_tree(root: str, max_files: int = 5000) -> list[SinkHit]:
    hits: list[SinkHit] = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if _lang_for(name) is None:
                continue
            count += 1
            if count > max_files:
                return hits
            hits.extend(scan_file(os.path.join(dirpath, name)))
    return hits


def prioritise(hits: Iterable[SinkHit]) -> list[SinkHit]:
    """Reachable-unsanitised paths first; the ranking lib supplies class weights."""
    from . import ranking
    return sorted(
        hits,
        key=lambda h: (
            h.has_nearby_source and not h.has_nearby_sanitiser,
            ranking.class_weight("source", h.cls),
        ),
        reverse=True,
    )
