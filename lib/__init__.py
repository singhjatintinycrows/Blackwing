"""Blackwing stdlib-only reasoning libraries.

Everything in this package must import only from the Python standard library so it runs
unchanged inside the minimal per-job sandbox. Web/orchestrator layers may use third-party
deps; `lib/` may not.
"""

__all__ = [
    "redact",
    "model_client",
    "audit",
    "scope",
    "findings",
    "validation",
    "ranking",
    "taint",
    "android_triage",
]
