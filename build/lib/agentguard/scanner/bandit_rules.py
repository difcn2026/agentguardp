"""
Bandit rule ID → AgentGuard rule ID mapping.
Maps common Bandit test IDs to fixer-compatible rule IDs.
"""
BANDIT_RULE_MAP = {
    # exec / eval
    "B102": "PY002",  # exec_used
    # pickle
    "B301": "PY005",  # pickle
    "B302": "PY007",  # marshal
    # crypto
    "B303": "PY030",  # md5
    "B304": "PY030",  # ciphers - map to md5 hash rule
    "B305": "PY031",  # cipher modes (manual)
    "B306": "PY032",  # mktemp → weak RNG
    # ssl/tls
    "B501": "PY042",  # ssl with bad defaults
    "B502": "PY042",  # ssl bad version
    "B503": "PY042",  # ssl bad defaults
    "B504": "PY042",  # ssl no hostname check
    "B505": "PY042",  # weak crypto
    "B506": "PY042",  # yaml load
    # shell injection
    "B601": "PY004",  # shell injection (unmapped - manual)
    "B602": "PY004",  # subprocess shell=True
    "B603": "PY004",  # subprocess without shell (manual)
    "B604": "PY004",  # any other process
    # hardcoded passwords
    "B105": "PY020",  # hardcoded password (manual)
    "B106": "PY020",  # hardcoded func args (manual)
    "B107": "PY020",  # hardcoded password default (manual)
    # other
    "B108": "PY060",  # hardcoded tmp file → DEBUG flag (stretch)
    "B110": "PY012",  # try except pass → tempfile
    "B201": "PY003",  # flask debug → os.system (manual)
    "B608": "PY003",  # sql injection → shell injection (stretch, manual)
    "B609": "PY003",  # unix wildcard → shell injection
    "B701": "PY061",  # jinja autoescape
}

def map_bandit_finding(finding: dict) -> dict:
    """Convert Bandit finding to AgentGuard-compatible format."""
    bid = finding.get("rule_id", "")
    mapped = BANDIT_RULE_MAP.get(bid, bid)
    # Keep original Bandit ID if no mapping exists
    if mapped == bid and not bid.startswith("PY"):
        mapped = "PY099"  # Generic fallback (won't be auto-fixed)
    return {
        "rule_id": mapped,
        "line": finding.get("line", 0),
        "file": finding.get("file", ""),
        "snippet": finding.get("code_snippet", finding.get("snippet", "")),
    }
