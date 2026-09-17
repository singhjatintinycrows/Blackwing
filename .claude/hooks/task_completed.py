import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _hooklib import read_event, stage_of, deny, allow, gate_or_allow

gate_or_allow()
ev = read_event()
stage = stage_of(ev)
out = ev.get("tool_input", ev.get("input", {})) or {}
# The completion payload is expected to carry these keys (the runner supplies them).
completion = ev.get("completion", out)

missing = []
if not completion.get("raw_output") and not completion.get("artifacts"):
    missing.append("raw tool output / artifacts")
if not completion.get("command_log"):
    missing.append("command log")
if stage in ("source-tracer", "android-hunter", "source-reporting", "android-reporting"):
    if not completion.get("traced_path") and not completion.get("evidence_ref"):
        missing.append("traced-path evidence (required by source/android methodology)")

if missing:
    deny("completion rejected — missing: " + "; ".join(missing))
allow()
