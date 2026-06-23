"""
AgentGuard LLM Heuristic Discovery v0.2
========================================
LLM-driven security review — finds vulnerabilities NO static rule can detect.

v0.2 (2026-06-20):
  - Multi-agent architecture: 5 specialized prompts per risk type (QASecClaw-inspired)
  - Coordinator agent for deduplication and prioritization
  - Sliding window chunks with 20% overlap (Local LLM Bug Detection paper)
  - Per-agent metrics tracking

Five risk types beyond pattern matching:
  1. race_condition   — shared state without locks in concurrent contexts
  2. swallowed_exception — except: pass / except: continue masking errors
  3. toctou           — time-of-check-time-of-use race windows
  4. missing_auth     — sensitive operations lacking authorization guards
  5. logic_bug        — logic contradictions leading to security bypass

Per spec: docs/spec/03-llm-heuristic-spec.md
Research: research/llm-heuristic-lit-review.md
DS Review: docs/eval/ds-architecture-review-20260619.md
"""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError

# ── Configuration ────────────────────────────────────────────────────

DS_API_URL = os.environ.get("DS_API_URL", "http://127.0.0.1:57321/v1/chat/completions")
DS_MODEL = os.environ.get("DS_MODEL", "deepseek-v4-flash")
DS_TIMEOUT = int(os.environ.get("DS_HEURISTIC_TIMEOUT", "15"))
DS_MAX_TOKENS = int(os.environ.get("DS_HEURISTIC_MAX_TOKENS", "512"))  # Per-agent, smaller
DS_TEMPERATURE = 0.05

MAX_LINES_PER_CHUNK = 300
CHUNK_OVERLAP = 0.2       # 20% overlap per Local LLM Bug Detection paper
MIN_CONFIDENCE = 0.6
CACHE = {}                # file_hash -> list[HeuristicFinding]
METRICS: Dict[str, list] = {"times": [], "finding_counts": [], "file_count": 0}


@dataclass
class HeuristicFinding:
    """A security risk found by LLM heuristic review — not rule-based."""
    file: str
    line_start: int
    line_end: int
    risk_type: str        # race_condition | swallowed_exception | toctou | missing_auth | logic_bug
    severity: str         # HIGH | MEDIUM | LOW
    confidence: float     # 0.0 - 1.0
    description: str
    suggestion: str
    source: str = "llm_heuristic"


# ── Multi-Agent Prompts ──────────────────────────────────────────────
# Each agent specializes in ONE risk type for higher precision (QASecClaw-inspired)

AGENT_RACE_CONDITION = """You are a concurrency security specialist.
Find ONLY race conditions: shared mutable state accessed in concurrent contexts (threading, asyncio, multiprocessing, subinterpreters) without proper synchronization (Lock, Semaphore, Queue, asyncio.Lock).

Look for:
- Global/shared variables modified in threads without locks
- Class attributes mutated across concurrent methods
- Dictionary/list mutations in signal handlers or callbacks
- File/database writes without file locking
- `threading.Thread` or `asyncio.create_task` touching shared state
- multiprocessing shared memory without synchronization

Do NOT report:
- Single-threaded code with no concurrency imports
- Code already inside `with lock:` blocks
- Read-only access to shared state

Respond in JSON ONLY: {"findings": [{"line_start": int, "line_end": int, "severity": "HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "description": "brief", "suggestion": "fix"}]}
If nothing found: {"findings": []}"""

AGENT_SWALLOWED_EXCEPTION = """You are an exception handling security specialist.
Your task: CONFIRM or REJECT SAST findings near try/except blocks. Do NOT generate new findings.

You receive a list of SAST findings. For each, classify:
- CONFIRMED: except genuinely masks security-relevant errors (auth, crypto, I/O, network, subprocess in try body)
- REJECTED: except is safe (specific error, test code, re-raises, harmless try body)

Confidence guide:
- 0.9-1.0: bare except:pass over security-sensitive operations
- 0.7-0.89: except:continue in loop with I/O or network
- 0.5-0.69: except SpecificError but try has mixed sensitivity
- <0.5: REJECTED — test code, re-raised, genuinely harmless

JSON ONLY: {"reviewed": [{"finding_id": "str", "line": int, "verdict": "CONFIRMED|REJECTED", "confidence": 0.0-1.0, "reason": "brief"}]}"""

# ── General SAST Confirmation Agent (NOT limited to try/except) ──────
AGENT_CONFIRM_SAST = """You are a code security verification specialist.
Your task: CONFIRM or REJECT static analysis findings. Do NOT generate new findings.

You receive SAST findings. For each one, decide based on the actual code context:
- CONFIRMED: the code genuinely has the described vulnerability
- REJECTED: the code is safe (test file, config only, properly sanitized, unreachable, or false pattern match)

Confidence guide:
- 0.9-1.0: clearly vulnerable (eval on user input, shell=True with variable, hardcoded secret, pickle on network data)
- 0.7-0.89: likely vulnerable but needs more context to be certain
- 0.5-0.69: probably safe but there's a non-trivial risk
- 0.3-0.49: likely false positive (test file, constant args, already validated)
JSON ONLY: {"reviewed": [{"finding_id": "str", "line": int, "verdict": "CONFIRMED|REJECTED", "confidence": 0.0-1.0, "reason": "brief"}]}"""

AGENT_TOCTOU = """You are a filesystem and TOCTOU security specialist.
Find ONLY time-of-check-time-of-use race conditions.

Look for:
- `os.path.exists(f)` / `os.access(f, ...)` followed by `open(f)` without exception handling
- `os.stat(...)` check then file operation on the same path
- Permission checks (if user.can_access) then action without re-validation
- Symlink races: checking then operating on paths that could be replaced
- Temporary file creation without `tempfile.mkstemp`
- Directory checks before operations in shared directories (/tmp, shared folders)
- Database record check-then-update without transactions or row locks

Do NOT report:
- Operations using `tempfile.mkstemp` or `tempfile.NamedTemporaryFile`
- Code already wrapped in try/except that handles the failure case
- Read-only operations where TOCTOU can't cause harm

Respond in JSON ONLY: {"findings": [{"line_start": int, "line_end": int, "severity": "HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "description": "brief", "suggestion": "fix"}]}
If nothing found: {"findings": []}"""

AGENT_MISSING_AUTH = """You are an authorization security specialist.
Find ONLY missing authorization checks before sensitive operations.

Look for:
- File read/write/delete operations without preceding permission validation
- Database queries returning data without checking user ownership
- Command execution (subprocess, os.system, os.popen) without authorization
- API endpoints/functions that access resources without auth decorators/checks
- Admin-only operations (config changes, user management) without role checks
- `@app.route('/admin/...')` or similar without `@login_required` or equivalent
- Sensitive data access (keys, tokens, PII) without access control

Context clues that suggest auth is missing:
- Function names like `delete_user`, `get_all_data`, `admin_action`
- Decorators like `@require_role` being absent on sensitive endpoints
- Comparison with neighboring functions that DO have auth checks

Do NOT report:
- Utility functions called from already-authorized contexts
- Test files
- Public API endpoints intentionally unauthenticated

Respond in JSON ONLY: {"findings": [{"line_start": int, "line_end": int, "severity": "HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "description": "brief", "suggestion": "fix"}]}
If nothing found: {"findings": []}"""

AGENT_LOGIC_BUG = """You are a logic and security bypass specialist.
Find ONLY logic bugs that could lead to security bypass.

Look for:
- Wrong comparison operators in auth/safety checks: `if x < 0:` instead of `if x <= 0:`
- Inverted booleans: `if not is_authenticated:` when checking authentication
- Off-by-one in boundary checks: `if index > len(arr):` (should be >=)
- Early returns that skip security checks
- Default-allow patterns: functions that proceed unless explicitly denied
- Type confusion: comparing string user IDs with integer IDs
- Missing negation: `if user.is_banned:` should be `if not user.is_banned:`
- Integer overflow in size/length checks before allocations
- Short-circuit logic errors: `if user and user.is_admin or is_public:` (missing parens)

Do NOT report:
- Style issues unrelated to security
- Performance optimizations that don't affect security
- Missing type hints

Respond in JSON ONLY: {"findings": [{"line_start": int, "line_end": int, "severity": "HIGH|MEDIUM|LOW", "confidence": 0.0-1.0, "description": "brief", "suggestion": "fix"}]}
If nothing found: {"findings": []}"""

# Agent registry
AGENTS = {
    "race_condition":       AGENT_RACE_CONDITION,
    "swallowed_exception":  AGENT_SWALLOWED_EXCEPTION,
    "toctou":              AGENT_TOCTOU,
    "missing_auth":        AGENT_MISSING_AUTH,
    "logic_bug":           AGENT_LOGIC_BUG,
}

# ── Core Functions ───────────────────────────────────────────────────

def _call_ds_api(messages: List[Dict], timeout: int = DS_TIMEOUT) -> Optional[Dict]:
    """Call DeepSeek API and return parsed JSON response."""
    # Try up to 2 times with increasing max_tokens
    for attempt, max_tok in enumerate([DS_MAX_TOKENS, DS_MAX_TOKENS * 2], 1):
        payload = json.dumps({
            "model": DS_MODEL,
            "messages": messages,
            "max_tokens": max_tok,
            "temperature": DS_TEMPERATURE,
            "response_format": {"type": "json_object"},
        }).encode("utf-8")

        req = Request(DS_API_URL, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")

        try:
            with urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                content = body["choices"][0]["message"]["content"]
                # Try direct parse first
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Attempt repair: find the last complete JSON object
                    if content.strip().startswith("{"):
                        # Try to close unclosed braces
                        repaired = content.rstrip()
                        open_b = repaired.count("{") - repaired.count("}")
                        open_s = repaired.count("[") - repaired.count("]")
                        repaired += "}" * open_b + "]" * open_s
                        try:
                            return json.loads(repaired)
                        except json.JSONDecodeError:
                            pass
                    if attempt == 1:
                        # Will retry with larger max_tokens
                        pass
                    else:
                        # Last resort: regex extraction of JSON objects from content
                        try:
                            # Find the outermost JSON object
                            match = re.search(r'\{(?:[^{}]|\{[^{}]*\})*\}', content)
                            if match:
                                extracted = json.loads(match.group())
                                return extracted
                        except (json.JSONDecodeError, re.error):
                            pass
                        # Try extracting individual reviewed items
                        try:
                            items = re.findall(r'\{"finding_id":[^}]+\}', content)
                            if items:
                                reviewed = []
                                for item in items:
                                    try:
                                        reviewed.append(json.loads(item))
                                    except json.JSONDecodeError:
                                        continue
                                if reviewed:
                                    return {"reviewed": reviewed}
                        except re.error:
                            pass
                        print(f"  [llm_heuristic] JSON parse failed after repair")
                        return None

        except (URLError, json.JSONDecodeError, KeyError, IndexError) as e:
            if attempt == 2:
                print(f"  [llm_heuristic] DS API error: {e}")
                return None
        time.sleep(0.3)  # Brief delay before retry

    return None


def _code_hash(code: str) -> str:
    """Stable hash for caching."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _build_user_prompt(code: str, existing_findings: list, start_line: int = 1) -> str:
    """Build the user message with existing findings summary and numbered code."""
    if existing_findings:
        summary_lines = []
        for f in existing_findings:
            fid = f.get("rule_id", f.get("risk_type", "?"))
            fline = f.get("line", f.get("line_start", "?"))
            fmsg = f.get("message", f.get("description", ""))[:80]
            summary_lines.append(f"  - [{fid}] L{fline}: {fmsg}")
        summary = "Existing findings (already handled):\n" + "\n".join(summary_lines)
    else:
        summary = "Existing findings: None."

    numbered_lines = []
    for i, line in enumerate(code.split("\n"), start=start_line):
        numbered_lines.append(f"{i:4d}| {line}")

    return f"""{summary}

Code to review:
```python
{chr(10).join(numbered_lines)}
```"""


def _chunk_code_overlap(code: str, max_lines: int = MAX_LINES_PER_CHUNK,
                        overlap: float = CHUNK_OVERLAP) -> List[Tuple[int, str]]:
    """Split code into overlapping sliding window chunks.

    Per Local LLM Bug Detection paper (Apr 2026):
    Sliding window with 20% overlap outperforms fixed disjoint chunks.
    """
    lines = code.split("\n")
    if len(lines) <= max_lines:
        return [(1, code)]

    stride = int(max_lines * (1.0 - overlap))
    if stride < 1:
        stride = max_lines

    chunks = []
    pos = 0
    while pos < len(lines):
        end = min(pos + max_lines, len(lines))
        chunk_text = "\n".join(lines[pos:end])
        chunks.append((pos + 1, chunk_text))  # 1-based line start
        pos += stride
    return chunks


def _parse_agent_response(result: Optional[Dict], file_path: str, risk_type: str,
                          chunk_start: int) -> List[HeuristicFinding]:
    """Parse raw JSON from one agent into HeuristicFinding list."""
    if result is None:
        return []

    raw_findings = result.get("findings", [])
    if not isinstance(raw_findings, list):
        return []

    valid_severities = {"HIGH", "MEDIUM", "LOW"}
    findings = []

    for rf in raw_findings:
        if not isinstance(rf, dict):
            continue

        severity = rf.get("severity", "MEDIUM").upper()
        confidence = float(rf.get("confidence", 0.0))

        if severity not in valid_severities:
            severity = "MEDIUM"
        if confidence < MIN_CONFIDENCE:
            continue

        findings.append(HeuristicFinding(
            file=file_path,
            line_start=int(rf.get("line_start", chunk_start)),
            line_end=int(rf.get("line_end", chunk_start)),
            risk_type=risk_type,
            severity=severity,
            confidence=round(confidence, 2),
            description=str(rf.get("description", ""))[:200],
            suggestion=str(rf.get("suggestion", ""))[:200],
        ))

    return findings


def _deduplicate_findings(findings: List[HeuristicFinding]) -> List[HeuristicFinding]:
    """Coordinator: deduplicate overlapping findings, keep highest confidence.

    Two findings overlap if same risk_type and line ranges intersect.
    Merged finding takes the wider line range and highest confidence.
    """
    if not findings:
        return []

    # Group by risk_type
    by_type: Dict[str, List[HeuristicFinding]] = {}
    for f in findings:
        by_type.setdefault(f.risk_type, []).append(f)

    deduped = []
    for risk_type, items in by_type.items():
        # Sort by line_start then confidence desc
        items.sort(key=lambda f: (f.line_start, -f.confidence))

        merged = []
        for f in items:
            # Check overlap with last merged finding
            if merged and merged[-1].line_end >= f.line_start:
                # Overlap: keep higher confidence, merge line range
                prev = merged[-1]
                if f.confidence > prev.confidence:
                    prev.confidence = f.confidence
                    prev.description = f.description
                    prev.suggestion = f.suggestion
                prev.line_end = max(prev.line_end, f.line_end)
            else:
                merged.append(f)

        deduped.extend(merged)

    # Second pass: cross-type dedup (same line range, different agents)
    deduped.sort(key=lambda f: (f.line_start, f.line_end, -f.confidence))
    final = []
    for f in deduped:
        if final and (f.line_start == final[-1].line_start
                      and f.line_end == final[-1].line_end):
            # Same location, different risk_type — keep both, but flag
            if f.confidence <= final[-1].confidence:
                continue  # Lower confidence duplicate, drop
        final.append(f)

    return final


def heuristic_scan_multi_agent(
    file_path: str,
    code: str,
    existing_findings: list,
    risk_types: Optional[List[str]] = None,
    use_cache: bool = True,
) -> List[HeuristicFinding]:
    """
    Run multi-agent heuristic review: one specialized agent per risk type.

    Per QASecClaw (May 2026): specialized agents achieve +23% F2 vs monolithic.

    Args:
        file_path: Path to the file.
        code: Full source code.
        existing_findings: Rule-based findings for this file.
        risk_types: Which agents to run (default: all 5).
        use_cache: Enable caching.

    Returns:
        Deduplicated list of HeuristicFinding across all agents.
    """
    # Cache check
    agent_key = ",".join(sorted(risk_types or AGENTS.keys()))
    file_hash = _code_hash(file_path + code + agent_key)
    if use_cache and file_hash in CACHE:
        return CACHE[file_hash]

    if risk_types is None:
        risk_types = list(AGENTS.keys())

    # Chunk code with overlap
    chunks = _chunk_code_overlap(code)

    all_findings: List[HeuristicFinding] = []
    total_api_calls = 0

    for chunk_start, chunk_text in chunks:
        user_prompt = _build_user_prompt(chunk_text, existing_findings, chunk_start)

        # Run each agent on this chunk (serial per spec, but agents are focused so faster)
        for risk_type in risk_types:
            agent_prompt = AGENTS.get(risk_type)
            if not agent_prompt:
                continue

            api_start = time.time()
            result = _call_ds_api([
                {"role": "system", "content": agent_prompt},
                {"role": "user", "content": user_prompt},
            ])
            api_elapsed = time.time() - api_start
            total_api_calls += 1

            if result is not None:
                agent_findings = _parse_agent_response(
                    result, file_path, risk_type, chunk_start
                )
                all_findings.extend(agent_findings)

            # Respect API rate — small delay between agents
            time.sleep(0.1)

        # Delay between chunks
        if len(chunks) > 1:
            time.sleep(0.2)

    # Coordinator: deduplicate
    final_findings = _deduplicate_findings(all_findings)

    # Record metrics
    METRICS["times"].append(time.time())
    METRICS["finding_counts"].append(len(final_findings))
    METRICS["file_count"] += 1

    # Cache
    if use_cache:
        CACHE[file_hash] = final_findings

    return final_findings


# ── Backward-compatible wrapper ──────────────────────────────────────

def heuristic_scan(
    file_path: str,
    code: str,
    existing_findings: list,
    api_url: str = DS_API_URL,
    model: str = DS_MODEL,
    use_cache: bool = True,
) -> List[HeuristicFinding]:
    """
    Single-file heuristic scan (backward-compatible).
    Now delegates to multi-agent pipeline internally.
    """
    return heuristic_scan_multi_agent(
        file_path=file_path,
        code=code,
        existing_findings=existing_findings,
        risk_types=None,  # All agents
        use_cache=use_cache,
    )


def heuristic_scan_files(
    file_map: Dict[str, str],
    existing_findings_map: Dict[str, list],
    use_cache: bool = True,
    risk_types: Optional[List[str]] = None,
) -> List[HeuristicFinding]:
    """
    Batch heuristic scan over multiple files using multi-agent pipeline.

    Args:
        file_map: {file_path: code_content}
        existing_findings_map: {file_path: [existing_findings]}
        use_cache: Enable caching.
        risk_types: Which agents to run (default: all).

    Returns:
        Combined list of HeuristicFinding across all files.
    """
    all_findings: List[HeuristicFinding] = []
    total = len(file_map)

    for i, (file_path, code) in enumerate(file_map.items(), 1):
        print(f"  [Labs] heuristic review {i}/{total}: {os.path.basename(file_path)}...", end=" ")
        start = time.time()

        existing = existing_findings_map.get(file_path, [])
        findings = heuristic_scan_multi_agent(
            file_path, code, existing, risk_types=risk_types, use_cache=use_cache
        )

        elapsed = time.time() - start
        if findings:
            print(f"{len(findings)} issues ({elapsed:.1f}s)")
        else:
            print(f"clean ({elapsed:.1f}s)")

        all_findings.extend(findings)

    return all_findings


def clear_cache():
    """Clear the heuristic scan cache."""
    CACHE.clear()


def confirm_sast_findings(
    file_path: str,
    code: str,
    sast_findings: list,
    use_cache: bool = True,
) -> List[dict]:
    """Paper 2 (SAST-Genius) compliant: confirm/reject SAST findings, NOT generate new ones.

    Uses the swallowed_exception agent to review try/except-related SAST findings.
    Only CONFIRMS or REJECTS — never generates new vulnerability reports.

    Returns: [{"finding_id": str, "line": int, "verdict": "CONFIRMED|REJECTED", "confidence": float, "reason": str}]
    """
    if not sast_findings:
        return []

    # Cache
    import hashlib
    findings_hash = hashlib.sha256(json.dumps(sast_findings, sort_keys=True).encode()).hexdigest()
    cache_key = f"confirm_{file_path}_{findings_hash}"
    if use_cache and cache_key in CACHE:
        return CACHE[cache_key]

    # Build review prompt
    findings_list = []
    for f in sast_findings:
        fid = f.get("rule_id", f.get("id", "?"))
        fline = f.get("line", f.get("line_start", 0))
        fmsg = f.get("message", f.get("description", ""))
        fsnippet = f.get("code_snippet", f.get("snippet", ""))
        findings_list.append(f"[{fid}] L{fline}: {fmsg}\n  Code: {fsnippet[:120]}")

    user_prompt = f"""SAST findings to review:
{chr(10).join(findings_list)}

Surrounding code context:
```python
{code[:3000]}
```"""

    result = _call_ds_api([
        {"role": "system", "content": AGENT_CONFIRM_SAST},
        {"role": "user", "content": user_prompt},
    ])

    if result is None:
        return []

    reviewed = result.get("reviewed", [])
    if not isinstance(reviewed, list):
        return []

    # Filter and validate
    valid = []
    for r in reviewed:
        if not isinstance(r, dict):
            continue
        verdict = r.get("verdict", "").upper()
        if verdict not in ("CONFIRMED", "REJECTED"):
            continue
        conf = float(r.get("confidence", 0.5))
        if conf < 0.5 and verdict == "CONFIRMED":
            continue  # Low confidence confirm = reject implicitly
        valid.append({
            "finding_id": r.get("finding_id", "?"),
            "line": int(r.get("line", 0)),
            "verdict": verdict,
            "confidence": round(conf, 2),
            "reason": str(r.get("reason", ""))[:200],
        })

    if use_cache:
        CACHE[cache_key] = valid

    return valid


def get_metrics() -> Dict:
    """Return current metrics for evaluation."""
    times = METRICS.get("times", [])
    counts = METRICS.get("finding_counts", [])
    return {
        "files_scanned": METRICS.get("file_count", 0),
        "total_findings": sum(counts),
        "avg_findings_per_file": sum(counts) / max(len(counts), 1),
        "enabled_agents": list(AGENTS.keys()),
        "chunk_overlap": CHUNK_OVERLAP,
        "cache_size": len(CACHE),
    }


# ── Display ──────────────────────────────────────────────────────────

def format_heuristic_results(findings: List[HeuristicFinding]) -> str:
    """Format heuristic findings for CLI/GUI display."""
    if not findings:
        return ""

    lines = [
        f"\n─── [Labs] LLM Heuristic Discovery ({len(findings)} findings) ───",
        "[!] Experimental: multi-agent review. Not from static rules. Review before acting.",
        "",
    ]

    by_type: Dict[str, List[HeuristicFinding]] = {}
    for f in findings:
        by_type.setdefault(f.risk_type, []).append(f)

    type_icons = {
        "race_condition": "[RC]",
        "swallowed_exception": "[SE]",
        "toctou": "[TO]",
        "missing_auth": "[MA]",
        "logic_bug": "[LB]",
    }

    for risk_type, items in sorted(by_type.items()):
        icon = type_icons.get(risk_type, "\u2022")
        lines.append(f"  {icon} {risk_type} ({len(items)}):")
        for f in items:
            lines.append(
                f"    [{f.severity}] L{f.line_start}-L{f.line_end} "
                f"(conf={f.confidence:.2f}): {f.description}"
            )
            if f.suggestion:
                lines.append(f"           Fix: {f.suggestion}")
        lines.append("")

    return "\n".join(lines)
