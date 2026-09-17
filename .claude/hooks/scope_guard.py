import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _hooklib import read_event, command_of, stage_of, deny, allow, gate_or_allow
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from lib import scope as scopelib

gate_or_allow()
ev = read_event()
cmd = command_of(ev)
stage = stage_of(ev)

scope_path = scopelib.find_scope()
if not scope_path:
    deny("no scope.yaml found — refusing to run any tool without an authorisation scope")
sc = scopelib.load(scope_path)

# 1) stage-level authorisation
if stage:
    ok, reason = sc.allows_stage(stage)
    if not ok:
        deny(f"stage '{stage}': {reason}")

# 2) target-in-scope checks against explicit allowlists
hosts = sc.in_scope_hosts
# crude host extraction from the command for network tools
url_hosts = set(re.findall(r'https?://([^/\s:"\']+)', cmd))
bare = set(re.findall(r'\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b', cmd, re.I))
candidates = url_hosts | bare
# ignore obvious non-targets
candidates = {h for h in candidates if not h.endswith(('.py', '.sh', '.json', '.txt', '.md', '.xml', '.yaml', '.yml'))}
if hosts and candidates:
    allowed = set()
    for h in candidates:
        if any(h == a or h.endswith('.' + a) for a in hosts):
            allowed.add(h)
    out_of_scope = candidates - allowed
    if out_of_scope:
        deny(f"target(s) not in scope allowlist: {sorted(out_of_scope)} (allowed: {hosts})")

allow(f"stage '{stage or 'n/a'}' within scope")
