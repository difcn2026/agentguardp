"""
AgentGuard Code Fixer v0.1
===========================
Standalone auto-fix engine. Reads scanner findings (JSON), applies fixes, outputs diff.

Interface:
  Input:  JSON array of findings [{rule_id, line, file, snippet}, ...]
  Output: {fixed_count, manual_count, diff, files: {path: fixed_content}}

Usage:
  python code_fixer.py findings.json --safe    # high-confidence only
  python code_fixer.py findings.json --fix     # all automatable
  python code_fixer.py findings.json --dry-run # preview only

Zero dependencies on agentguard internals.
"""
import json
import re
import sys
from pathlib import Path
from difflib import unified_diff
from typing import List, Dict, Optional, Tuple

# ── Transform Registry ──
# rule_id -> {confidence, fix(pattern, line), imports}

def _sub(pattern, replacement):
    """Create a regex substitution fixer."""
    return lambda line: re.sub(pattern, replacement, line)

TRANSFORMS: Dict[str, dict] = {
    # ═══ Code Injection ═══
    "PY001": {  # eval() -> ast.literal_eval()
        "confidence": 0.98,
        "fix": lambda line: re.sub(r"\beval\s*\((.+?)\)$", r"ast.literal_eval(\1)", line),
        "imports": ["import ast"],
        "category": "injection",
    },
    "PY002": {  # exec() — manual only
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "injection",
    },
    "PY003": {  # os.system() — manual (needs full rewrite)
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "injection",
    },
    "PY004": {  # shell=True -> shell=False
        "confidence": 1.0,
        "fix": lambda line: line.replace("shell=True", "shell=False"),
        "imports": [],
        "category": "injection",
    },
    "PY005": {  # pickle.loads -> json.loads
        "confidence": 0.95,
        "fix": lambda line: re.sub(r"\bpickle\.(loads?|Unpickler)\s*\(", r"json.loads(", line),
        "imports": ["import json"],
        "category": "injection",
    },
    "PY006": {  # yaml.load -> yaml.safe_load
        "confidence": 1.0,
        "fix": lambda line: line.replace("yaml.load(", "yaml.safe_load(").replace(
            "yaml.load_all(", "yaml.safe_load_all("),
        "imports": [],
        "category": "injection",
    },
    "PY007": {  # marshal.loads -> json.loads
        "confidence": 0.95,
        "fix": lambda line: re.sub(r"\bmarshal\.loads?\s*\(", r"json.loads(", line),
        "imports": ["import json"],
        "category": "injection",
    },

    # ═══ Path Traversal ═══
    "PY010": {  # os.path.realpath — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "path",
    },
    "PY011": {  # path allowlist — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "path",
    },
    "PY012": {  # tempfile.mktemp -> NamedTemporaryFile
        "confidence": 1.0,
        "fix": lambda line: re.sub(r"\btempfile\.mktemp\s*\(", "tempfile.NamedTemporaryFile(delete=False, ", line),
        "imports": [],
        "category": "path",
    },

    # ═══ Secrets ═══
    "PY020": {  # hardcoded secret — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "secrets",
    },
    "PY021": {  # key outside repo — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "secrets",
    },
    "PY022": {  # .env in .gitignore — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "secrets",
    },

    # ═══ Weak Crypto ═══
    "PY030": {  # hashlib.md5/sha1 -> sha256
        "confidence": 1.0,
        "fix": lambda line: re.sub(r"\bhashlib\.(md5|sha1)\s*\(", "hashlib.sha256(", line),
        "imports": [],
        "category": "crypto",
    },
    "PY031": {  # weak hash -> sha256
        "confidence": 1.0,
        "fix": lambda line: re.sub(r"\bhashlib\.(md5|sha1)\s*\(", "hashlib.sha256(", line),
        "imports": [],
        "category": "crypto",
    },
    "PY032": {  # random.* -> secrets.*
        "confidence": 0.95,
        "fix": lambda line: re.sub(r"\brandom\.(choice|randint|random)\s*\(", r"secrets.\1(", line),
        "imports": ["import secrets"],
        "category": "crypto",
    },

    # ═══ SSRF / URL ═══
    "PY040": {  # URL validation — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "ssrf",
    },
    "PY041": {  # URL allowlist — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "ssrf",
    },
    "PY042": {  # verify=False -> verify=True
        "confidence": 1.0,
        "fix": lambda line: line.replace("verify=False", "verify=True"),
        "imports": [],
        "category": "ssrf",
    },

    # ═══ LLM / Prompt ═══
    "PY050": {  # prompt sanitize — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "llm",
    },
    "PY051": {  # auth decorator — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "llm",
    },
    "PY052": {  # max iterations — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "llm",
    },

    # ═══ Config / Debug ═══
    "PY060": {  # DEBUG=True -> DEBUG=False
        "confidence": 1.0,
        "fix": lambda line: line.replace("DEBUG = True", "DEBUG = False").replace(
            "DEBUG=True", "DEBUG=False"),
        "imports": [],
        "category": "config",
    },
    "PY061": {  # assert( -> assert (
        "confidence": 0.95,
        "fix": lambda line: line.replace("assert(", "assert ("),
        "imports": [],
        "category": "config",
    },
    "PY083": {  # SQL injection — LLM fix
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "injection",
    },
    "PY084": {  # Hardcoded password — LLM fix
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "secrets",
    },
    # ═══ JavaScript/TypeScript ═══
    "JS001": {  # eval — LLM fix (context-dependent)
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "injection",
    },
    "JS010": {  # innerHTML -> textContent
        "confidence": 0.95,
        "fix": lambda line: line.replace(".innerHTML", ".textContent"),
        "imports": [],
        "category": "xss",
    },
    "JS012": {  # document.write — manual
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "xss",
    },
    "JS030": {  # hardcoded password — LLM fix
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "secrets",
    },
    "JS040": {  # md5 -> sha256
        "confidence": 1.0,
        "fix": lambda line: line.replace("md5", "sha256"),
        "imports": [],
        "category": "crypto",
    },
    "JS041": {  # sha1 -> sha256
        "confidence": 1.0,
        "fix": lambda line: line.replace("sha1", "sha256"),
        "imports": [],
        "category": "crypto",
    },
    "JS060": {  # rejectUnauthorized: false -> true
        "confidence": 1.0,
        "fix": lambda line: line.replace("rejectUnauthorized: false", "rejectUnauthorized: true"),
        "imports": [],
        "category": "network",
    },
    "JS020": {  # SQL injection — LLM fix
        "confidence": 0.0,
        "fix": None,
        "manual": True,
        "category": "injection",
    },
}



# ── Cloud LLM fix (GLM-5.2 via VPS) ──
# For rules marked manual:True, send to cloud API for context-aware fix.
# Cloud verifies license + calls GLM-5.2 server-side. Client cannot bypass.

_CLOUD_FIX_URL = "https://agentguardp.com:8991/api/fix"
_CLOUD_TIMEOUT = 60


def _cloud_fix_file(file_path, findings, rule_descriptions, source_lines):
    """Send manual findings to cloud API for LLM fix. Returns (fixed_lines, results)."""
    import json as _json
    from urllib.request import Request as _Req
    from urllib.request import urlopen as _urlopen

    lines = list(source_lines)
    results = []
    imports_to_add = set()

    # Get license key
    from pathlib import Path as _P
    license_path = _P.home() / ".agentguard" / "license.key"
    license_key = ""
    if license_path.exists():
        license_key = license_path.read_text().strip()

    # Check trial
    if not license_key:
        trial_path = _P.home() / ".agentguard" / "trial.json"
        if trial_path.exists():
            import json as _j2
            from datetime import datetime as _dt
            try:
                trial = _j2.loads(trial_path.read_text())
                install = _dt.strptime(trial.get("install_date",""), "%Y-%m-%d")
                if (_dt.utcnow() - install).days < 14:
                    # Trial active — use trial key format
                    license_key = "AgentGuard-TRIAL"
            except Exception:
                pass

    if not license_key:
        for f in findings:
            rid = f.get("rule_id", "")
            if TRANSFORMS.get(rid, {}).get("manual"):
                results.append({
                    "rule_id": rid, "line": f.get("line",0), "fixed": False,
                    "reason": "Pro license required for LLM fix (https://agentguardp.com)",
                })
        return lines, results, imports_to_add

    # Prepare manual findings for cloud
    manual_findings = []
    for f in findings:
        rid = f.get("rule_id", "")
        if TRANSFORMS.get(rid, {}).get("manual"):
            manual_findings.append({"rule_id": rid, "line": f.get("line", 0)})

    if not manual_findings:
        return lines, results, imports_to_add

    # Call cloud API
    payload = _json.dumps({
        "license_key": license_key,
        "findings": manual_findings,
        "source_lines": source_lines,
        "rule_descriptions": rule_descriptions,
    }).encode("utf-8")

    req = _Req(_CLOUD_FIX_URL, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with _urlopen(req, timeout=_CLOUD_TIMEOUT) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        for f in manual_findings:
            results.append({
                "rule_id": f["rule_id"], "line": f["line"], "fixed": False,
                "reason": f"Cloud fix unavailable: {e}",
            })
        return lines, results, imports_to_add

    if "error" in data:
        for f in manual_findings:
            results.append({
                "rule_id": f["rule_id"], "line": f["line"], "fixed": False,
                "reason": data["error"],
            })
        return lines, results, imports_to_add

    # Apply cloud fixes
    for r in data.get("results", []):
        rid = r.get("rule_id", "")
        line_no = r.get("line", 0)
        if r.get("fixed") and r.get("fixed_code"):
            fixed_code = r["fixed_code"]
            fixed_lines = fixed_code.split("\n")
            if len(fixed_lines) == 1:
                lines[line_no - 1] = fixed_lines[0]
            else:
                lines[line_no - 1:line_no] = fixed_lines
            for fl in fixed_lines:
                if fl.strip().startswith("import ") or fl.strip().startswith("from "):
                    imports_to_add.add(fl.strip())
            results.append({
                "rule_id": rid, "line": line_no, "fixed": True,
                "original": r.get("original",""), "fixed": fixed_code,
                "fixer": "cloud-glm-5.2",
            })
        else:
            results.append({
                "rule_id": rid, "line": line_no, "fixed": False,
                "reason": r.get("reason", "cloud fix failed"),
            })

    return lines, results, imports_to_add


def fix_file(file_path: str, findings: list, mode: str = "safe") -> Tuple[str, List[dict], set]:
    """
    Apply fixes to one file based on its findings.
    Returns (fixed_source, results[], new_imports).
    """
    src = Path(file_path).read_text(encoding="utf-8")
    lines = src.split("\n")
    results = []
    imports_to_add = set()

    for f in sorted(findings, key=lambda x: x.get("line", 0)):
        rid = f.get("rule_id", "")
        line_no = f.get("line", 0)
        snippet = f.get("snippet", "")

        if line_no < 1 or line_no > len(lines):
            continue

        tx = TRANSFORMS.get(rid)
        if not tx:
            results.append({"rule_id": rid, "line": line_no, "fixed": False, "reason": "unknown rule"})
            continue

        confidence = tx.get("confidence", 0)
        is_manual = tx.get("manual", False)

        # Mode filtering
        if mode == "safe" and confidence < 0.90:
            results.append({"rule_id": rid, "line": line_no, "fixed": False,
                            "reason": "below safe threshold (%.0f%%)" % (confidence * 100)})
            continue
        if is_manual:
            results.append({"rule_id": rid, "line": line_no, "fixed": False, "reason": "manual review"})
            continue

        # Apply
        try:
            original = lines[line_no - 1]
            fix_fn = tx.get("fix")
            if fix_fn:
                fixed = fix_fn(original)
                if fixed != original:
                    lines[line_no - 1] = fixed
                    results.append({"rule_id": rid, "line": line_no, "fixed": True,
                                    "original": original, "fixed": fixed})
                    for imp in tx.get("imports", []):
                        imports_to_add.add(imp)
                else:
                    results.append({"rule_id": rid, "line": line_no, "fixed": False,
                                    "reason": "no change applied"})
        except Exception as e:
            results.append({"rule_id": rid, "line": line_no, "fixed": False,
                            "reason": "error: %s" % str(e)})

    # Inject new imports AFTER all fixes (avoids line number interference)
    if imports_to_add:
        existing = set(l.strip() for l in lines[:40])
        new_imports = [i for i in sorted(imports_to_add) if i not in existing]
        if new_imports:
            last_import = 0
            for i, l in enumerate(lines[:60]):
                if l.startswith(("import ", "from ")):
                    last_import = i + 1
            for imp in reversed(new_imports):
                lines.insert(last_import, imp)

    # ── LLM fix pass: for manual rules, try GLM-5.2 ──
    manual_findings = [f for f in findings if TRANSFORMS.get(f.get("rule_id", ""), {}).get("manual")]
    if manual_findings:
        try:
            from agentguard.rules.python_rules import PYTHON_RULES as _RULES
            rule_descs = {}
            for r in _RULES:
                sev = r.severity.value if hasattr(r.severity, 'value') else str(r.severity)
                rule_descs[r.rule_id] = {"description": r.description, "severity": sev, "fix": r.fix}
        except Exception:
            rule_descs = {}

        llm_lines, llm_results, llm_imports = _cloud_fix_file(
            file_path, manual_findings, rule_descs, lines
        )
        lines = llm_lines
        results.extend(llm_results)
        imports_to_add.update(llm_imports)

    # ── P2: Syntax validation after fix ──
    fixed_source = "\n".join(lines)
    try:
        import ast as _ast
        _ast.parse(fixed_source)
    except SyntaxError as _se:
        # Fix introduced syntax error — revert this file
        import sys as _sys
        _sys.stderr.write(f"[code_fixer] Syntax error after fix: {_se} — reverting\n")
        return src, [{"rule_id": "SYNTAX_CHECK", "line": 0, "fixed": False,
                       "reason": f"Fix would break syntax: {_se}"}], set()

    return fixed_source, results, imports_to_add


def run(findings_input, mode: str = "safe", write: bool = False) -> dict:
    """
    Main entry point.

    findings_input: JSON file path or list of findings dicts.
    mode: "safe" | "fix" | "dry-run"
    write: actually write fixed files back to disk.

    Returns summary dict with diff and stats.
    """
    # Load findings
    if isinstance(findings_input, str):
        findings = json.loads(Path(findings_input).read_text(encoding="utf-8"))
    else:
        findings = findings_input

    # Normalize: accept {"findings": [...]} wrapper from agentguard scan --format json
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    # Normalize field names: scanner uses code_snippet, fixer uses snippet
    for f in findings:
        if "code_snippet" in f and "snippet" not in f:
            f["snippet"] = f["code_snippet"]

    # Resolve relative paths: relative to findings file, or CWD
    base_dir = Path.cwd()
    if isinstance(findings_input, str):
        base_dir = Path(findings_input).parent.resolve()

    # Group by file
    by_file: Dict[str, list] = {}
    for f in findings:
        fp = f.get("file", "unknown.py")
        by_file.setdefault(fp, []).append(f)

    all_results = []
    all_diffs = []
    fixed_files = {}
    fixed_count = 0
    manual_count = 0

    for file_path, file_findings in by_file.items():
        resolved = Path(file_path)
        if not resolved.is_absolute():
            resolved = base_dir / file_path
        if not resolved.exists():
            continue
        file_path = str(resolved)

        original = Path(file_path).read_text(encoding="utf-8")
        fixed_src, results, imports = fix_file(file_path, file_findings, mode)

        all_results.extend(results)
        fixed_count += sum(1 for r in results if r["fixed"])
        manual_count += sum(1 for r in results if not r["fixed"])

        if fixed_src != original:
            diff = "".join(unified_diff(
                original.splitlines(keepends=True),
                fixed_src.splitlines(keepends=True),
                fromfile="a/" + file_path,
                tofile="b/" + file_path,
            ))
            if diff:
                all_diffs.append(diff)
            fixed_files[file_path] = fixed_src

            if write and mode != "dry-run":
                Path(file_path).write_text(fixed_src, encoding="utf-8")

    return {
        "mode": mode,
        "total_findings": len(findings),
        "fixed_count": fixed_count,
        "manual_count": manual_count,
        "files_changed": len(fixed_files),
        "diff": "\n".join(all_diffs),
        "files": fixed_files,
        "results": all_results,
    }


# ── CLI ──
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="AgentGuard Code Fixer")
    p.add_argument("findings", help="JSON file with scanner findings")
    p.add_argument("--safe", action="store_true", help="High-confidence fixes only (~100%%)")
    p.add_argument("--fix", action="store_true", help="Apply all automatable fixes")
    p.add_argument("--dry-run", action="store_true", help="Preview diff, no file changes")
    p.add_argument("--write", action="store_true", help="Write fixes to disk")
    p.add_argument("--json", action="store_true", help="Output as JSON")

    args = p.parse_args()

    mode = "safe"
    if args.fix:
        mode = "fix"
    if args.dry_run:
        mode = "dry-run"

    result = run(args.findings, mode=mode, write=args.write)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if result["diff"]:
            print(result["diff"])
        print()
        print("Fixed: %d  |  Manual: %d  |  Files: %d  |  Mode: %s" % (
            result["fixed_count"], result["manual_count"],
            result["files_changed"], result["mode"]))
        if result["manual_count"] > 0:
            manual = [r for r in result["results"] if not r["fixed"]]
            for r in manual:
                print("  [%s] L%d: %s" % (r.get("rule_id", ""), r.get("line", 0), r.get("reason", "")))
