import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _hooklib import read_event, command_of, tool_of, stage_of, allow, gate_or_allow
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from lib import audit

gate_or_allow()
ev = read_event()
job_dir = os.environ.get("BLACKWING_JOB_DIR", os.getcwd())
try:
    log = audit.open_log(job_dir)
    log.append("tool_call", {
        "tool": tool_of(ev),
        "stage": stage_of(ev),
        "command": command_of(ev),
        "exit_code": ev.get("exit_code"),
    })
except Exception as e:  # never let audit failure block the pipeline; report to stderr
    sys.stderr.write(f"[blackwing:audit] warning: {e}\n")
allow()
