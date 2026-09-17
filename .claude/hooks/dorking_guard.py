import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _hooklib import read_event, command_of, deny, allow, gate_or_allow

gate_or_allow()
ev = read_event()
cmd = command_of(ev).lower()

# Search-operator laundering that constitutes dorking, and the engines it targets.
DORK_OPERATORS = [r'\bsite:', r'\binurl:', r'\bintitle:', r'\bintext:', r'\bfiletype:',
                  r'\bext:', r'\bcache:', r'\brelated:', r'\ballintext:', r'\ballinurl:']
GH_DORK = [r'\bpath:', r'\bfilename:', r'\bextension:', r'\blanguage:', r'in:file',
           r'\borg:\S+\s+\S+', ]
SEARCH_TARGETS = ['google.com/search', 'bing.com/search', 'duckduckgo.com',
                  'api.github.com/search', 'github.com/search', 'search?q=']

has_operator = any(re.search(p, cmd) for p in DORK_OPERATORS)
hits_search_engine = any(t in cmd for t in SEARCH_TARGETS)
gh_dork = any(re.search(p, cmd) for p in GH_DORK) and ('github' in cmd or 'search?q=' in cmd)

if has_operator and (hits_search_engine or 'curl' in cmd or 'wget' in cmd or 'http' in cmd):
    deny("Google/GitHub dorking is disabled in all tracks (search operator against a search engine)")
if gh_dork:
    deny("GitHub code-search dorking is disabled in all tracks")
if hits_search_engine and re.search(r'q=[^&\s]*(site|inurl|filetype|intitle)(%3a|:)', cmd):
    deny("dorking query detected in search-engine URL")

allow()
