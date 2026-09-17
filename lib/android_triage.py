"""Android static-triage engine for Track C.

Parses a decoded AndroidManifest.xml and enumerates reachable entry points in the
methodology's triage order: exported components with no permission first, then deep
links / App Links, intent redirection, WebView, ContentProviders, implicit intents, then
secrets/storage/network, resilience last.

stdlib-only: uses ``xml.etree`` for the manifest. The decode step (apktool/jadx) runs
upstream in the sandbox; this consumes the decoded tree.
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_A = f"{{{ANDROID_NS}}}"


@dataclass
class Component:
    kind: str                      # activity / service / receiver / provider
    name: str
    exported: Optional[bool]       # None = default (depends on intent-filters / SDK)
    permission: str = ""
    has_intent_filter: bool = False
    deep_link_schemes: list[str] = field(default_factory=list)
    autoverify: bool = False
    grant_uri_permissions: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def effectively_exported(self) -> bool:
        if self.exported is True:
            return True
        if self.exported is None and self.has_intent_filter:
            return True   # pre-S implicit export via intent-filter
        return False


@dataclass
class ManifestSummary:
    package: str = ""
    version_code: str = ""
    version_name: str = ""
    target_sdk: str = ""
    min_sdk: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext: Optional[bool] = None
    components: list[Component] = field(default_factory=list)


def _to_bool(v: Optional[str]) -> Optional[bool]:
    if v is None:
        return None
    return v.strip().lower() == "true"


def parse_manifest(path: str) -> ManifestSummary:
    tree = ET.parse(path)
    root = tree.getroot()
    summ = ManifestSummary(package=root.get("package", ""))
    summ.version_code = root.get(f"{_A}versionCode", "")
    summ.version_name = root.get(f"{_A}versionName", "")

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        summ.target_sdk = uses_sdk.get(f"{_A}targetSdkVersion", "")
        summ.min_sdk = uses_sdk.get(f"{_A}minSdkVersion", "")

    app = root.find("application")
    if app is not None:
        summ.debuggable = _to_bool(app.get(f"{_A}debuggable")) or False
        summ.allow_backup = _to_bool(app.get(f"{_A}allowBackup"))
        if summ.allow_backup is None:
            summ.allow_backup = True
        summ.uses_cleartext = _to_bool(app.get(f"{_A}usesCleartextTraffic"))
        for kind_tag, kind in (("activity", "activity"), ("activity-alias", "activity"),
                               ("service", "service"), ("receiver", "receiver"),
                               ("provider", "provider")):
            for el in app.findall(kind_tag):
                summ.components.append(_parse_component(el, kind))
    return summ


def _parse_component(el, kind: str) -> Component:
    name = el.get(f"{_A}name", "")
    exported = _to_bool(el.get(f"{_A}exported"))
    permission = el.get(f"{_A}permission", "") or el.get(f"{_A}readPermission", "") or el.get(f"{_A}writePermission", "")
    intent_filters = el.findall("intent-filter")
    comp = Component(
        kind=kind, name=name, exported=exported, permission=permission,
        has_intent_filter=bool(intent_filters),
        grant_uri_permissions=_to_bool(el.get(f"{_A}grantUriPermissions")) or False,
    )
    for f in intent_filters:
        if _to_bool(f.get(f"{_A}autoVerify")):
            comp.autoverify = True
        for data in f.findall("data"):
            scheme = data.get(f"{_A}scheme")
            if scheme:
                comp.deep_link_schemes.append(scheme)
    return comp


# -- triage: emit candidates in methodology priority order --------------------
def triage(summ: ManifestSummary) -> list[dict]:
    """Return ordered candidate dicts (cls + why + component) for the hunter to trace."""
    out: list[dict] = []

    def add(cls, comp: Component, why):
        out.append({"cls": cls, "component": comp.name, "kind": comp.kind, "why": why})

    for c in summ.components:
        if c.effectively_exported and not c.permission:
            add("exported-no-permission", c,
                "exported with no permission guard — reachable by any app")
        elif c.effectively_exported and c.permission:
            add("exported-component", c, f"exported, guarded by permission {c.permission}")
    for c in summ.components:
        if c.deep_link_schemes:
            cls = "app-link" if c.autoverify else "deep-link"
            add(cls, c, f"handles schemes {sorted(set(c.deep_link_schemes))}"
                        f"{' (autoVerify)' if c.autoverify else ''}")
    for c in summ.components:
        if c.kind == "provider" and c.effectively_exported:
            add("content-provider", c,
                f"exported provider{' with grantUriPermissions' if c.grant_uri_permissions else ''}")
    # app-level resilience/hygiene (report only if it protects something that matters)
    if summ.debuggable:
        out.append({"cls": "resilience", "component": "application", "kind": "app",
                    "why": "android:debuggable=true in shipped manifest"})
    if summ.allow_backup:
        out.append({"cls": "insecure-storage", "component": "application", "kind": "app",
                    "why": "allowBackup=true — app data extractable via adb backup"})
    if summ.uses_cleartext:
        out.append({"cls": "network", "component": "application", "kind": "app",
                    "why": "usesCleartextTraffic=true"})

    from . import ranking
    return ranking.triage_order("android", out)


SECRET_HINTS = [
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private_key"),
    (re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*[=:]\s*\S{8,}"), "generic_secret"),
]


def scan_strings_for_secrets(decoded_root: str, max_files: int = 3000) -> list[dict]:
    """Report secret *kind and location* only — never the value (radioactive)."""
    out: list[dict] = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(decoded_root):
        dirnames[:] = [d for d in dirnames if d not in {".git"}]
        for name in filenames:
            if not name.endswith((".xml", ".json", ".smali", ".properties", ".txt", ".js")):
                continue
            count += 1
            if count > max_files:
                return out
            fpath = os.path.join(dirpath, name)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        for pat, kind in SECRET_HINTS:
                            if pat.search(line):
                                out.append({"cls": "secrets", "kind": kind,
                                            "location": f"{os.path.relpath(fpath, decoded_root)}:{lineno}"})
                                break
            except OSError:
                continue
    return out
