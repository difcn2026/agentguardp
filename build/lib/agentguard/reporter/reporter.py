"""
AgentGuard Reporter v0.1
=========================
Output formats: terminal (rich), JSON, SARIF, Markdown.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from ..scanner.code_scanner import ScanResult, Finding, Severity

CST = timezone(timedelta(hours=8))


def _severity_icon(sev: Severity) -> str:
    icons = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }
    return icons.get(sev, "⚪")


def terminal_report(result: ScanResult, verbose: bool = False) -> str:
    """Rich terminal output using plain text (no rich dependency for v0.1)."""
    lines = []
    lines.append("")
    lines.append("╔══════════════════════════════════════════════╗")
    lines.append("║        AgentGuard Security Scan Report       ║")
    lines.append("╚══════════════════════════════════════════════╝")
    lines.append("")
    lines.append(f"  Path scanned : {result.path}")
    lines.append(f"  Files        : {result.files_scanned}")
    lines.append(f"  Lines        : {result.total_lines:,}")
    lines.append(f"  Time         : {datetime.now(CST).strftime('%Y-%m-%d %H:%M:%S')} CST")
    lines.append("")

    # Summary
    if result.total_findings == 0:
        lines.append("  ✅ No security issues found!")
    else:
        lines.append("  ┌─────────── Summary ───────────┐")
        lines.append(f"  │ 🔴 CRITICAL : {result.critical_count:>3}             │")
        lines.append(f"  │ 🟠 HIGH     : {result.high_count:>3}             │")
        lines.append(f"  │ 🟡 MEDIUM   : {result.medium_count:>3}             │")
        lines.append(f"  │ 🔵 LOW      : {result.low_count:>3}             │")
        lines.append(f"  │ 📋 TOTAL    : {result.total_findings:>3}             │")
        lines.append("  └────────────────────────────────┘")
        lines.append("")

        # Findings
        lines.append("  ── Findings ──")
        for i, finding in enumerate(result.findings, 1):
            icon = _severity_icon(finding.severity)
            lines.append(f"  {i:3}. {icon} [{finding.rule_id}] {finding.message[:100]}")
            lines.append(f"       📁 {finding.file}:{finding.line}:{finding.column}")

            if verbose and finding.code_snippet:
                snippet = finding.code_snippet[:100]
                lines.append(f"       💻 {snippet}")
            if verbose and finding.fix:
                lines.append(f"       💡 {finding.fix}")
            lines.append("")

    # Errors
    if result.errors:
        lines.append("  ── Errors ──")
        for err in result.errors:
            lines.append(f"  ⚠️  {err}")
        lines.append("")

    # Verdict
    if result.passed:
        lines.append("  ✅ VERDICT: PASS — No critical or high-severity issues.")
    else:
        issues = result.critical_count + result.high_count
        lines.append(f"  ❌ VERDICT: FAIL — {issues} critical/high issues need attention.")

    lines.append("")
    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    """JSON output for CI/CD integration."""
    return json.dumps({
        "tool": "AgentGuard",
        "version": "0.5.0",
        "timestamp": datetime.now(CST).isoformat(),
        "path": result.path,
        "files_scanned": result.files_scanned,
        "total_lines": result.total_lines,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "total": result.total_findings,
        },
        "passed": result.passed,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "message": f.message,
                "code_snippet": f.code_snippet,
                "fix": f.fix,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }, indent=2, ensure_ascii=False)


def sarif_report(result: ScanResult) -> str:
    """SARIF (Static Analysis Results Interchange Format) output v2.1.0."""
    rules_set = set()
    results = []
    for f in result.findings:
        rules_set.add(f.rule_id)
        results.append({
            "ruleId": f.rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {
                        "startLine": max(1, f.line),
                        "startColumn": max(1, f.column + 1),
                    }
                }
            }],
        })

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentGuard",
                    "version": "0.5.0",
                    "informationUri": "https://github.com/xhls/agentguard",
                    "rules": [{"id": rid, "name": rid} for rid in rules_set],
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _sarif_level(sev: Severity) -> str:
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "warning",
        Severity.INFO: "note",
    }
    return mapping.get(sev, "warning")


def markdown_report(result: ScanResult) -> str:
    """Markdown report for PR comments / GitHub."""
    lines = []
    lines.append("# AgentGuard Security Scan Report")
    lines.append("")
    lines.append(f"**Path:** `{result.path}` | **Files:** {result.files_scanned} | **Lines:** {result.total_lines:,}")
    lines.append("")

    if result.total_findings == 0:
        lines.append("✅ **No security issues found.**")
    else:
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| 🔴 CRITICAL | {result.critical_count} |")
        lines.append(f"| 🟠 HIGH | {result.high_count} |")
        lines.append(f"| 🟡 MEDIUM | {result.medium_count} |")
        lines.append(f"| 🔵 LOW | {result.low_count} |")
        lines.append("")

        for f in result.findings:
            icon = _severity_icon(f.severity)
            lines.append(f"### {icon} {f.rule_id}: {f.message}")
            lines.append(f"- **File:** `{f.file}:{f.line}`")
            if f.code_snippet:
                lines.append(f"- **Code:** `{f.code_snippet[:80]}`")
            if f.fix:
                lines.append(f"- **Fix:** {f.fix}")
            lines.append("")

    return "\n".join(lines)
