"AgentGuard Pipeline - scan -> filter -> fix, one command."
import sys, json
from pathlib import Path
from dataclasses import dataclass, field

from .scanner.code_scanner import CodeScanner
from fixer.code_fixer import run as fixer_run


class FakeFinding:
    "Minimal finding wrapper for Bandit output."
    def __init__(self, d):
        self.rule_id = d.get("rule_id", "")
        self.line = d.get("line", 0)
        self.file = d.get("file", "")
        self.code_snippet = d.get("code_snippet", "")
        self.message = d.get("message", "")
        self.severity = d.get("severity", "LOW")
        self.confidence = 1.0


@dataclass
class ScanWrapper:
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list = field(default_factory=list)


def _scan(path, tier):
    scanner = CodeScanner(tier=tier)
    return scanner.scan_directory(str(Path(path).resolve()))


def _scan_bandit(path):
    from .scanner.bandit_adapter import scan_with_bandit
    raw = scan_with_bandit(str(Path(path).resolve()))
    result = ScanWrapper()
    for f in raw:
        sev = f.get("severity", "LOW")
        if sev == "CRITICAL": result.critical_count += 1
        elif sev == "HIGH": result.high_count += 1
        elif sev == "MEDIUM": result.medium_count += 1
        else: result.low_count += 1
    result.findings = [FakeFinding(f) for f in raw]
    result.total_findings = len(result.findings)
    return result


def pipeline(path=".", mode="dry-run", use_ds=False, write=False, tier="pro", use_bandit=False):
    summary = {"path": path, "mode": mode, "engine": "bandit" if use_bandit else "builtin"}

    print("[1/3] Scanning...")
    print(f"      Engine: {'Bandit (100+ rules)' if use_bandit else 'AgentGuard built-in (11 rules)'}")
    if use_bandit:
        result = _scan_bandit(path)
    else:
        result = _scan(path, tier)

    total = result.total_findings
    print(f"      {total} findings ({result.critical_count} crit, {result.high_count} high)")

    # ML filter only for built-in scanner; Bandit findings all keep confidence 1.0
    if not use_bandit:
        high_conf = [f for f in result.findings if f.confidence >= 0.5]
        low_conf = [f for f in result.findings if f.confidence < 0.5]
        print(f"      ML filtered: {len(low_conf)} low-confidence dropped")
        for f in low_conf:
            print(f"        - {f.rule_id} L{f.line}: {f.code_snippet[:50]}")
        current = high_conf
    else:
        current = result.findings

    summary["scan"] = {"total": total, "critical": result.critical_count, "high": result.high_count}

    # Phase 2: DS Review
    if use_ds and current:
        print(f"\n[2/3] DeepSeek reviewing {len(current)} findings...")
        try:
            from .scanner.llm_review import review_finding
            tp, fp, unk = [], [], []
            for f in current:
                classification, conf, reason = review_finding(
                    rule_id=f.rule_id,
                    severity=f.severity if isinstance(f.severity, str) else f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    message=f.message,
                    code_snippet=f.code_snippet or "",
                )
                if classification == "TRUE_POSITIVE": tp.append(f)
                elif classification == "FALSE_POSITIVE": fp.append(f)
                else: unk.append(f)
            print(f"      TP:{len(tp)}  FP:{len(fp)}  UNK:{len(unk)}")
            current = tp + unk
            summary["ds_review"] = {"tp": len(tp), "fp": len(fp), "unk": len(unk)}
        except Exception as e:
            print(f"      DS unavailable ({e})")
    else:
        print(f"\n[2/3] DS review skipped")

    # Phase 3: Fix
    print(f"\n[3/3] Fixing {len(current)} findings (mode={mode})...")
    if not current:
        print("      Nothing to fix.")
        summary["fix"] = {"fixed_count": 0, "manual_count": 0, "files_changed": 0, "diff": ""}
        return summary

    fixer_input = [{"rule_id": f.rule_id, "line": f.line, "file": f.file, "snippet": f.code_snippet or ""} for f in current]
    # Map Bandit rule IDs to AgentGuard-fixer compatible IDs
    if use_bandit:
        from .scanner.bandit_rules import map_bandit_finding
        fixer_input = [map_bandit_finding(f) for f in fixer_input]
    fix_result = fixer_run(fixer_input, mode=mode, write=write)
    print(f"      Fixed: {fix_result['fixed_count']}  |  Manual: {fix_result['manual_count']}  |  Files: {fix_result['files_changed']}")
    if fix_result.get("diff"):
        print(fix_result["diff"])
    summary["fix"] = fix_result
    return summary


def cmd_pipeline(args):
    pipeline(
        path=args.path,
        mode=args.mode,
        use_ds=args.ds,
        write=args.write,
        use_bandit=getattr(args, "bandit", False),
    )
