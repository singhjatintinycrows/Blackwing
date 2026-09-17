import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _hooklib import read_event, command_of, deny, allow, gate_or_allow
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from lib import redact

gate_or_allow()
ev = read_event()
cmd = command_of(ev)

# 1) A command that contains a live secret AND writes/sends it is denied.
kinds = redact.contains_secret(cmd)
WRITE_OR_SEND = re.compile(
    r'(>>?|tee\b|cp\b|mv\b|dd\b|curl\b.*(-d|--data|-F|-H)|wget\b.*--post|nc\b|'
    r'git\s+(add|commit|push)|echo\b.*>)', re.I)
# Writing a secret into a file under jobs/ artifacts or reports is forbidden (radioactive).
WRITES_TO_ARTIFACT = re.compile(r'(jobs/|artifacts/|report|findings|command_log|audit_log)', re.I)

if kinds:
    if WRITE_OR_SEND.search(cmd):
        deny(f"secret ({', '.join(sorted(set(kinds)))}) in a write/send command — refused; "
             f"secrets are reported by kind+location only, never persisted or transmitted")
    if WRITES_TO_ARTIFACT.search(cmd):
        deny(f"secret ({', '.join(sorted(set(kinds)))}) headed for an artifact/report path — refused")

# 2) Never write env/token files to disk outside a tmpfs/in-memory path.
if re.search(r'AWS_BEARER_TOKEN_BEDROCK|GITHUB_TOKEN|GH_TOKEN', cmd) and WRITE_OR_SEND.search(cmd):
    if not re.search(r'/dev/shm|/run/|memfd', cmd):
        deny("credential env var being written outside an in-memory path — refused")

allow()
