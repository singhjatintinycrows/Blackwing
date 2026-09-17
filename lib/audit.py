"""Hash-chained, append-only, secret-redacted audit log.

Every tool call the engine makes is appended as one JSON line whose ``prev`` field is the
SHA-256 of the previous entry's canonical bytes. Tampering with any past line breaks the
chain and ``verify()`` reports the first broken index. All string values are passed through
``redact`` before they touch disk, so a leaked secret never lands in the log.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Iterator, Optional

from . import redact

_GENESIS = "0" * 64


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


def _hash(entry: dict) -> str:
    return hashlib.sha256(_canonical(entry)).hexdigest()


class AuditLog:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _last_hash(self) -> str:
        last = _GENESIS
        if not os.path.exists(self.path):
            return last
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["hash"]
        return last

    def append(self, event: str, data: Optional[dict] = None, **extra) -> dict:
        payload = redact.redact_obj({**(data or {}), **extra})
        entry = {
            "ts": round(time.time(), 3),
            "event": event,
            "data": payload,
            "prev": self._last_hash(),
        }
        entry["hash"] = _hash(entry)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def __iter__(self) -> Iterator[dict]:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> tuple[bool, Optional[int]]:
        """Return (ok, first_broken_index). ok=True and index=None means intact."""
        prev = _GENESIS
        for i, entry in enumerate(self):
            expected_hash = entry.get("hash")
            body = {k: entry[k] for k in entry if k != "hash"}
            if entry.get("prev") != prev or _hash(body) != expected_hash:
                return False, i
            prev = expected_hash
        return True, None


def open_log(job_dir: str) -> AuditLog:
    return AuditLog(os.path.join(job_dir, "audit_log.jsonl"))
