"""Shared helpers for Blackwing hooks.

Hooks receive the tool-call as JSON on stdin (Claude Code / Codex PreToolUse shape):

    {"tool_name": "Bash", "tool_input": {"command": "..."}, "stage": "02-active-web"}

Convention: exit 0 = allow, exit 2 = DENY (reason on stderr). Fail closed on parse errors
for guard hooks. These helpers keep the individual hook scripts tiny and make `lib/` the
single source of truth for the rules.
"""
from __future__ import annotations

import json
import os
import sys

# Make `lib` importable regardless of where the hook is invoked from.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


def engine_active() -> bool:
    """True only when running inside the engine/sandbox context, which the trusted
    orchestrator marks by exporting ``BLACKWING_ENGINE=1``. The guards fail CLOSED in this
    context and stay inactive during platform development so they don't gate the build shell.
    A stray scope.yaml also activates enforcement (defence in depth)."""
    if os.environ.get("BLACKWING_ENGINE") == "1":
        return True
    return False


def gate_or_allow() -> None:
    """Short-circuit a guard to allow when not in engine context."""
    if not engine_active():
        allow("dev/build context — control plane inactive")


def read_event() -> dict:
    try:
        data = sys.stdin.read()
        return json.loads(data) if data.strip() else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def command_of(event: dict) -> str:
    ti = event.get("tool_input", event.get("input", {})) or {}
    return ti.get("command") or ti.get("cmd") or ""


def tool_of(event: dict) -> str:
    return event.get("tool_name") or event.get("tool") or ""


def stage_of(event: dict) -> str:
    return (
        event.get("stage")
        or os.environ.get("BLACKWING_STAGE")
        or ""
    )


def deny(reason: str) -> "NoReturn":  # type: ignore[name-defined]
    sys.stderr.write(f"[blackwing:deny] {reason}\n")
    sys.exit(2)


def allow(note: str = "") -> "NoReturn":  # type: ignore[name-defined]
    if note:
        sys.stderr.write(f"[blackwing:allow] {note}\n")
    sys.exit(0)
