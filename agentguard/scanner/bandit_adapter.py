"""
AgentGuard Bandit Adapter v0.1
===============================
Uses Bandit (100+ rules) as scanning engine, outputs AgentGuard-compatible findings.
Then feeds into ML filter + DS review + Fixer pipeline.
"""
import json, subprocess, sys, tempfile
from pathlib import Path
from typing import List, Dict


def scan_with_bandit(target: str) -> List[Dict]:
    """
    Run Bandit on target, return findings in AgentGuard format.

    Returns list of findings with keys:
        rule_id, severity, file, line, message, code_snippet
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        subprocess.run(
            [sys.executable, "-m", "bandit", "-r", target, "-f", "json", "-o", tmp_path, "-q"],
            capture_output=True, timeout=120
        )
        with open(tmp_path, encoding="utf-8") as f:
            bandit_output = json.load(f)
    except Exception as e:
        print(f"  Bandit error: {e}")
        return []
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    findings = []
    for result in bandit_output.get("results", []):
        severity_map = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}
        findings.append({
            "rule_id": result.get("test_id", "B000"),
            "severity": severity_map.get(result.get("issue_severity", "LOW"), "LOW"),
            "file": result.get("filename", ""),
            "line": result.get("line_number", 0),
            "message": result.get("issue_text", ""),
            "code_snippet": result.get("code", ""),
            "confidence": result.get("issue_confidence", "MEDIUM"),
        })

    # Filter out findings with MEDIUM confidence
    findings = [f for f in findings if f.get("confidence") != "MEDIUM"]
    return findings


def bandit_scan_to_findings_json(target: str, output_path: str = None) -> list:
    """Convenience: scan and write AgentGuard-format JSON."""
    findings = scan_with_bandit(target)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        print(f"Saved {len(findings)} findings to {output_path}")
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = scan_with_bandit(target)
    print(f"Bandit found {len(findings)} findings")
    for f in findings[:10]:
        print(f"  {f['rule_id']} L{f['line']}: {f['message'][:60]}")
    if len(findings) > 10:
        print(f"  ... and {len(findings) - 10} more")
