"""Ephemeral in-memory secrets store.

The GitHub token (and any other job credential) is a credential, not a form value. It is
held only in memory, keyed by an opaque ``token_ref``, for the lifetime of the operation
that needs it (the clone). ``scope.yaml`` and every artifact store the ``token_ref``, never
the raw secret. ``discard()`` wipes it once the clone completes; ``secret_guard.sh`` blocks
any attempt to write it to disk.

This is a process-local default implementation. In production, back it with a real secrets
manager (Vault / AWS Secrets Manager) by implementing the same tiny interface; do NOT persist
tokens to the job directory.
"""
from __future__ import annotations

import os
import secrets as _secrets
import threading
from typing import Optional


class SecretsStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: dict[str, str] = {}

    def put(self, value: str, hint: str = "token") -> str:
        """Store *value*, return an opaque reference handle to record in scope/artifacts."""
        ref = f"secret://{hint}/{_secrets.token_urlsafe(12)}"
        with self._lock:
            self._store[ref] = value
        # Register for exact redaction everywhere it might otherwise leak.
        try:
            import sys
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if root not in sys.path:
                sys.path.insert(0, root)
            from lib import redact
            redact.register_extra_secrets([value])
        except Exception:
            pass
        return ref

    def get(self, ref: str) -> Optional[str]:
        with self._lock:
            return self._store.get(ref)

    def discard(self, ref: str) -> None:
        """Wipe a single secret once its operation completes."""
        with self._lock:
            if ref in self._store:
                # overwrite before delete to reduce residency
                self._store[ref] = "\x00" * len(self._store[ref])
                del self._store[ref]

    def discard_all(self) -> None:
        with self._lock:
            for k in list(self._store):
                self._store[k] = "\x00" * len(self._store[k])
            self._store.clear()


# Process-wide default instance.
STORE = SecretsStore()
