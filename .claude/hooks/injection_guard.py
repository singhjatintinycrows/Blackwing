import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _hooklib import read_event, command_of, deny, allow, gate_or_allow

gate_or_allow()
ev = read_event()
cmd = command_of(ev)
low = cmd.lower()

EXECUTORS = r'(bash|sh|zsh|python[0-9.]*|perl|ruby|node|php|eval|exec)'
# fetch-then-execute: curl/wget ... | sh   (a hostile string driving execution)
FETCH_EXEC = re.compile(r'(curl|wget|fetch)\b[^|;]*\|\s*' + EXECUTORS, re.I)
# decode-then-execute: base64 -d / atob / xxd | sh   (laundering an obfuscated payload)
DECODE_EXEC = re.compile(r'(base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d|atob)\b[^|;]*\|\s*' + EXECUTORS, re.I)
# eval of a decode
EVAL_DECODE = re.compile(r'eval\b.*(base64|atob|\\x[0-9a-f]{2})', re.I)

if FETCH_EXEC.search(cmd):
    deny("fetch-then-execute blocked: piping downloaded content into an interpreter")
if DECODE_EXEC.search(cmd):
    deny("decode-then-execute blocked: piping decoded bytes into an interpreter")
if EVAL_DECODE.search(cmd):
    deny("eval-of-decoded-payload blocked")
allow()
