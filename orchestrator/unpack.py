"""Safe upload validation and archive extraction.

The web app is network-facing, so every uploaded artifact is hostile until proven otherwise:

* **Magic-byte validation** — confirm a file is really what it claims by its content, not its
  extension (an ``.apk`` that is actually an ELF, or an ``.png`` that is a ZIP, is rejected).
* **Zip-slip protection** — an APK is a ZIP; reject any entry whose resolved path escapes the
  extraction root, plus absolute paths and symlink entries. This is the CVE-2020-8913-shaped
  mistake, avoided here rather than merely hunted for elsewhere.
* **Size / count limits** — cap total uncompressed size and entry count to stop zip bombs.

stdlib-only.
"""
from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass

# (label, offset, magic bytes)
_MAGIC = {
    "zip": (0, b"PK\x03\x04"),        # also APK/AAB/JAR (all ZIP)
    "zip_empty": (0, b"PK\x05\x06"),
    "elf": (0, b"\x7fELF"),
    "png": (0, b"\x89PNG\r\n\x1a\n"),
    "pdf": (0, b"%PDF"),
    "dex": (0, b"dex\n"),
}

DEFAULT_MAX_UNCOMPRESSED = 2 * 1024 * 1024 * 1024   # 2 GiB
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_MAX_RATIO = 200                              # uncompressed/compressed guard


class UnpackError(Exception):
    pass


def sniff(path: str) -> str:
    """Return the detected file-type label, or 'unknown'."""
    with open(path, "rb") as fh:
        head = fh.read(16)
    for label, (off, magic) in _MAGIC.items():
        if head[off:off + len(magic)] == magic:
            return "zip" if label == "zip_empty" else label
    return "unknown"


def validate_kind(path: str, expected: str) -> None:
    """Raise UnpackError unless *path*'s real content matches *expected*.

    expected: 'apk'/'aab'/'zip' all require ZIP magic; 'pdf', 'png', etc. use their magic.
    """
    kind = sniff(path)
    if expected in ("apk", "aab", "zip", "jar"):
        if kind != "zip":
            raise UnpackError(f"expected a ZIP-family file ({expected}) but content is {kind!r}")
    elif kind != expected:
        raise UnpackError(f"expected {expected!r} but content is {kind!r}")


@dataclass
class ExtractResult:
    root: str
    entries: int
    total_uncompressed: int
    skipped: list[str]


def _is_within(base: str, target: str) -> bool:
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return target == base or target.startswith(base + os.sep)


def safe_extract_zip(
    archive: str,
    dest: str,
    max_uncompressed: int = DEFAULT_MAX_UNCOMPRESSED,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_ratio: int = DEFAULT_MAX_RATIO,
) -> ExtractResult:
    """Extract *archive* into *dest*, refusing any entry that escapes *dest*.

    Rejects (raises UnpackError) on: path traversal (``../``), absolute member paths, drive
    or UNC prefixes, symlink members, and size/count/ratio limits. Directory entries are
    created; regular files are written; anything else is skipped and recorded.
    """
    os.makedirs(dest, exist_ok=True)
    dest_real = os.path.realpath(dest)
    total = 0
    count = 0
    skipped: list[str] = []

    if not zipfile.is_zipfile(archive):
        raise UnpackError("not a valid ZIP archive")

    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise UnpackError(f"too many entries: {len(infos)} > {max_entries}")
        compressed_total = sum(i.compress_size for i in infos) or 1

        for info in infos:
            name = info.filename
            # Absolute paths, drive letters, UNC.
            if name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
                raise UnpackError(f"absolute path in archive entry: {name!r}")
            # Normalise and confirm containment BEFORE writing anything.
            target = os.path.join(dest_real, name)
            if not _is_within(dest_real, os.path.dirname(target) or dest_real) or \
               not _is_within(dest_real, target):
                raise UnpackError(f"zip-slip: entry escapes extraction root: {name!r}")
            # Symlink members (mode high bits) are refused — a symlink can redirect a later write.
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                skipped.append(f"symlink:{name}")
                continue

            count += 1
            total += info.file_size
            if total > max_uncompressed:
                raise UnpackError(f"uncompressed size exceeds {max_uncompressed} bytes (zip bomb?)")

            if name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                # stream copy so a single huge member can't blow memory
                while True:
                    chunk = src.read(1024 * 64)
                    if not chunk:
                        break
                    out.write(chunk)

        if total / compressed_total > max_ratio and total > 10 * 1024 * 1024:
            raise UnpackError(
                f"compression ratio {total // compressed_total}x exceeds {max_ratio}x (zip bomb?)")

    return ExtractResult(root=dest, entries=count, total_uncompressed=total, skipped=skipped)
