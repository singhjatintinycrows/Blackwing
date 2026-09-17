"""scope.yaml loading and the authorisation decision used by scope_guard.sh.

This module is the *reference* implementation of the authorisation rules. The hook shells
out to it so the same logic guards every tool call. It has no third-party YAML dependency —
it parses the small, known-shape scope file with a minimal loader.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

# Stages that never send packets / touch a running target — allowed pre-approval.
PASSIVE_STAGES = {
    "01-passive-osint", "05-threat-intel", "04-cloud-enum",  # web passive
    "source-orient", "source-tracer", "source-reporting",     # source is all static
    "android-recon", "android-hunter",                         # apk static analysis
    "planning", "reporting", "analysis-correlation",
}
# Stages that send packets / call live APIs / touch a running app — gated on approval.
ACTIVE_STAGES = {
    "02-active-web", "03-network-discovery", "08-nuclei-hunter", "09-access-control",
    "10-validation", "xss", "sqli", "ssrf", "ssti", "idor",   # web active
    "android-dynamic",                                          # on-device PoC
}


class _Frame:
    __slots__ = ("indent", "container", "parent", "key")

    def __init__(self, indent, container, parent=None, key=None):
        self.indent = indent
        self.container = container   # dict or list currently being filled
        self.parent = parent         # parent container of `container` (for map<->list fixup)
        self.key = key               # key in parent under which `container` lives


def _minimal_yaml_load(text: str) -> dict:
    """Tiny YAML subset loader for scope files (mappings, lists, scalars, nesting by
    indentation). Avoids a PyYAML dependency so lib/ stays stdlib-only.

    Handles the one tricky case — an empty-value key whose children turn out to be a list —
    by tentatively creating a dict and converting it to a list on the first ``- item``.
    """
    root: dict = {}
    stack: list[_Frame] = [_Frame(-1, root)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if line.startswith("- "):
            val = _scalar(line[2:].strip())
            # Drop frames strictly deeper than this list item.
            while len(stack) > 1 and indent < stack[-1].indent:
                stack.pop()
            top = stack[-1]
            if isinstance(top.container, list):
                top.container.append(val)
            else:
                # The pushed empty-key dict is actually a list — convert in place.
                if top.parent is not None and top.key is not None:
                    top.parent[top.key] = [val]
                    top.container = top.parent[top.key]
            continue

        # key: value line — pop frames at equal-or-deeper indent.
        while len(stack) > 1 and indent <= stack[-1].indent:
            stack.pop()
        parent = stack[-1].container
        if ":" not in line:
            continue
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest == "":
            new: dict = {}
            parent[key] = new
            stack.append(_Frame(indent, new, parent, key))
        elif rest == "[]":
            parent[key] = []
        else:
            parent[key] = _scalar(rest)
    return root


def _scalar(s: str):
    s = s.strip().strip('"').strip("'")
    if s.lower() in ("true", "false"):
        return s.lower() == "true"
    if s == "":
        return ""
    return s


@dataclass
class Scope:
    raw: dict = field(default_factory=dict)

    @property
    def job_id(self) -> str:
        return str(self.raw.get("job_id", ""))

    @property
    def authorised(self) -> bool:
        return bool(self.raw.get("authorised", False))

    @property
    def authority_reference(self) -> str:
        return str(self.raw.get("authority", {}).get("reference", "") or "")

    @property
    def in_scope_hosts(self) -> list[str]:
        return list(self.raw.get("targets", {}).get("web", {}).get("in_scope_hosts", []) or [])

    @property
    def repo_url(self) -> str:
        return str(self.raw.get("targets", {}).get("source", {}).get("repo_url", "") or "")

    @property
    def package_name(self) -> str:
        return str(self.raw.get("targets", {}).get("android", {}).get("package_name", "") or "")

    def constraint(self, name: str, default=True) -> bool:
        return bool(self.raw.get("constraints", {}).get(name, default))

    # -- the authorisation decision ----------------------------------------
    def allows_stage(self, stage: str) -> tuple[bool, str]:
        """Return (allowed, reason). Passive stages always allowed; active stages require
        authorised=True with a recorded authority reference."""
        if stage in PASSIVE_STAGES:
            return True, "passive/static stage — allowed pre-approval"
        if stage in ACTIVE_STAGES:
            if not self.authority_reference:
                return False, "active stage denied: no authority.reference recorded"
            if not self.authorised:
                return False, "active stage denied: scope not authorised (human approval pending)"
            return True, "active stage — authorised and approved"
        # Unknown stage: fail closed.
        return False, f"unknown stage '{stage}' — failing closed"


def load(path: str) -> Scope:
    with open(path, "r", encoding="utf-8") as fh:
        return Scope(raw=_minimal_yaml_load(fh.read()))


def find_scope(start: Optional[str] = None) -> Optional[str]:
    """Locate scope.yaml via env or by walking up from cwd."""
    env = os.environ.get("BLACKWING_SCOPE")
    if env and os.path.exists(env):
        return env
    d = os.path.abspath(start or os.getcwd())
    while True:
        candidate = os.path.join(d, "scope.yaml")
        if os.path.exists(candidate):
            return candidate
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent
