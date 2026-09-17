"""Tests for upload safety: magic-byte validation and zip-slip protection."""
import os
import zipfile

import pytest

from orchestrator import unpack


def test_magic_byte_rejects_fake_apk(tmp_path):
    fake = tmp_path / "fake.apk"
    fake.write_bytes(b"not a zip at all")
    with pytest.raises(unpack.UnpackError):
        unpack.validate_kind(str(fake), "apk")


def test_magic_byte_accepts_real_zip(tmp_path):
    good = tmp_path / "good.apk"
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")
    unpack.validate_kind(str(good), "apk")  # no raise
    assert unpack.sniff(str(good)) == "zip"


def test_safe_extract_ok(tmp_path):
    arc = tmp_path / "a.zip"
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr("a/b.txt", "hello")
        z.writestr("c.txt", "world")
    r = unpack.safe_extract_zip(str(arc), str(tmp_path / "out"))
    assert r.entries == 2
    assert (tmp_path / "out" / "a" / "b.txt").read_text() == "hello"


def test_zip_slip_blocked(tmp_path):
    arc = tmp_path / "evil.zip"
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr("../../../../tmp/pwned_test.txt", "owned")
    with pytest.raises(unpack.UnpackError):
        unpack.safe_extract_zip(str(arc), str(tmp_path / "out"))
    assert not os.path.exists("/tmp/pwned_test.txt")


def test_absolute_path_blocked(tmp_path):
    arc = tmp_path / "abs.zip"
    with zipfile.ZipFile(arc, "w") as z:
        z.writestr("/etc/evil", "no")
    with pytest.raises(unpack.UnpackError):
        unpack.safe_extract_zip(str(arc), str(tmp_path / "out"))


def test_too_many_entries(tmp_path):
    arc = tmp_path / "many.zip"
    with zipfile.ZipFile(arc, "w") as z:
        for i in range(50):
            z.writestr(f"f{i}", "x")
    with pytest.raises(unpack.UnpackError):
        unpack.safe_extract_zip(str(arc), str(tmp_path / "out"), max_entries=10)
