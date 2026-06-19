"""
AgentGuard Pro CLI v0.3.0
==========================
Command-line interface for AgentGuard Pro 鈥?Scanner + Auto-Fixer.

Usage:
    agentguard scan ./my-project
    agentguard fix findings.json --mode fix
    agentguard activate AGENTGUARD-xxxx.yyyy
    agentguard status
    agentguard deactivate
"""

import sys
from pathlib import Path

# Fix Unicode emoji output on Windows GBK terminals
if sys.platform == "win32":
    for stream in ("stdout", "stderr"):
        try:
            s = getattr(sys, stream)
            if s is not None and hasattr(s, "reconfigure"):
                s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from .scanner.code_scanner import CodeScanner
from .reporter.reporter import terminal_report, json_report, sarif_report, markdown_report
from .license_verify import (
    activate as license_activate,
    get_active_tier,
    deactivate as license_deactivate,
    get_machine_hash,
)
from fixer.code_fixer import run as fixer_run
from .pipeline import cmd_pipeline
from .desktop import serve as desktop_serve


def scan(
    path: str = ".",
    *,
    format: str = "terminal",
    output: str = "",
    verbose: bool = False,
    tier: str = None,
    files: list = None,
):
    """Scan a directory or files for security issues."""
    if tier is None:
        tier = get_active_tier()

    target = Path(path)
    if not target.exists():
        print(f"Error: Path not found: {path}", file=sys.stderr)
        sys.exit(1)

    scanner = CodeScanner(tier=tier)
    result = scanner.scan_directory(str(target), files=files)

    reporters = {
        "terminal": terminal_report,
        "json": json_report,
        "sarif": sarif_report,
        "markdown": markdown_report,
    }

    reporter = reporters.get(format, terminal_report)
    if format == "terminal":
        report_text = reporter(result, verbose=verbose)
    else:
        report_text = reporter(result)

    if output:
        Path(output).write_text(report_text, encoding="utf-8")
        print(f"Report saved to: {output}")
    else:
        print(report_text)

    if not result.passed:
        sys.exit(1)


def main():
    """Entry point for console_scripts."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AgentGuard Pro 鈥?AI Code Security Scanner + Auto-Fixer",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ---- scan ----
    scan_parser = subparsers.add_parser("scan", help="Scan code for security issues")
    scan_parser.add_argument("path", default=".", nargs="?", help="Directory or file to scan")
    scan_parser.add_argument("--format", "-f", default="terminal",
                             choices=["terminal", "json", "sarif", "markdown"],
                             help="Output format (default: terminal)")
    scan_parser.add_argument("--output", "-o", default="", help="Output file path")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    scan_parser.add_argument("--tier", default=None, choices=["free", "pro"],
                             help="License tier (default: auto-detect from activated license)")
    scan_parser.add_argument("--version", action="version", version="AgentGuard Pro v0.3.0")

    # ---- activate ----
    activate_parser = subparsers.add_parser("activate", help="Activate a license key")
    activate_parser.add_argument("key", help="License key (e.g., AGENTGUARD-xxxx.yyyy)")

    # ---- status ----
    subparsers.add_parser("status", help="Show license status and machine hash")
    subparsers.add_parser("serve", help="Start desktop web GUI")

    # ---- deactivate ----
    subparsers.add_parser("deactivate", help="Deactivate license on this machine")

    # ---- fix ----
    fix_parser = subparsers.add_parser("fix", help="Auto-fix findings from a previous scan")
    fix_parser.add_argument("findings", help="Path to findings JSON file from agentguard scan --format json")
    fix_parser.add_argument("--mode", "-m", default="dry-run",
                           choices=["safe", "fix", "dry-run"],
                           help="Fix mode: safe, fix, dry-run (default)")
    fix_parser.add_argument("--write", "-w", action="store_true", help="Write fixes to disk")

    # ---- pipeline (scan + filter + fix) ----
    pipe_parser = subparsers.add_parser("pipeline", aliases=["auto-fix"], help="Full pipeline: scan -> filter -> fix")
    pipe_parser.add_argument("path", default=".", nargs="?", help="Directory or file to scan")
    pipe_parser.add_argument("--mode", "-m", default="dry-run",
                           choices=["safe", "fix", "dry-run"],
                           help="Fix mode (default: dry-run)")
    pipe_parser.add_argument("--ds", action="store_true", help="Enable DeepSeek secondary review")
    pipe_parser.add_argument("--write", "-w", action="store_true", help="Write fixes to disk")
    pipe_parser.add_argument("--bandit", action="store_true", help="Use Bandit engine (100+ rules) instead of built-in")

    args = parser.parse_args()

    if args.command == "scan":
        scan(
            path=args.path,
            format=args.format,
            output=args.output,
            verbose=args.verbose,
            tier=args.tier,
        )
    elif args.command == "activate":
        license_activate(args.key)
    elif args.command == "status":
        tier = get_active_tier()
        print(f"Tier      : {tier}")
        print(f"Machine ID: {get_machine_hash()}")
        print(f"Status    : {'Activated' if tier != 'free' else 'Free (no license)'}")
    elif args.command == "deactivate":
        license_deactivate()
        print("License deactivated. Back to free tier.")
    elif args.command == "fix":
        result = fixer_run(args.findings, mode=args.mode, write=args.write)
        print(f"\nFixed: {result['fixed_count']}  |  Manual: {result['manual_count']}  |  Files: {result['files_changed']}  |  Mode: {result['mode']}")
        if result.get('diff'):
            print(result['diff'])
        for r in result.get('results', []):
            print(f"  [{r['rule_id']}] L{r['line']}: {r.get('reason', r.get('fixed', ''))}")
    elif args.command in ("pipeline", "auto-fix"):
        cmd_pipeline(args)
    elif args.command == "serve":
        desktop_serve()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

