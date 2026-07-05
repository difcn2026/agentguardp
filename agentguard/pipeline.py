"AgentGuard Pipeline - scan -> confirm -> review -> fix, one command."
import sys, json, os
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


def _confirm_filter(findings):
    """Phase 2: Run confirmation agent on raw findings. CONFIRMED/REJECTED."""
    if not findings:
        return [], [], []

    from .scanner.llm_review import LLMReviewer

    reviewer = LLMReviewer()
    confirmed, rejected, errors = [], [], []

    for f in findings:
        try:
            classification, confidence, reason = reviewer.review(f)
            if classification == 'TRUE_POSITIVE':
                if hasattr(f, 'confidence'):
                    f.confidence = confidence
                confirmed.append(f)
            elif classification == 'FALSE_POSITIVE':
                rejected.append(f)
            else:  # UNKNOWN => keep, don't lose signal
                confirmed.append(f)
        except Exception as e:
            # DS unavailable: keep the finding
            confirmed.append(f)

    return confirmed, rejected, errors


def pipeline(path=".", mode="dry-run", use_glm=False, write=False, tier="pro", use_bandit=False, use_labs=False):
    summary = {"path": path, "mode": mode, "engine": "bandit" if use_bandit else "builtin"}

    # Phase 1: Scan
    print("[1/4] Scanning...")
    print(f"      Engine: {'Bandit (100+ rules)' if use_bandit else 'AgentGuard built-in (11 rules)'}")
    if use_bandit:
        result = _scan_bandit(path)
    else:
        result = _scan(path, tier)

    total = result.total_findings
    print(f"      {total} findings ({result.critical_count} crit, {result.high_count} high)")

    if not use_bandit:
        high_conf = [f for f in result.findings if f.confidence >= 0.5]
        low_conf = [f for f in result.findings if f.confidence < 0.5]
        print(f"      ML filtered: {len(low_conf)} low-confidence dropped")
        current = high_conf
    else:
        current = result.findings

    summary["scan"] = {"total": total, "critical": result.critical_count, "high": result.high_count}

    # Phase 2: Confirmation Agent (BEFORE DS Review)
    if current:
        print(f"\n[2/4] Confirmation agent on {len(current)} findings...")
        try:
            confirmed, rejected, cf_errors = _confirm_filter(current)
            fp_removed = len(rejected)
            # Fallback: if confirmation returned nothing (DS API failure), keep all findings
            if len(confirmed) == 0 and len(rejected) == 0 and len(cf_errors) == 0:
                print(f"      CONFIRMED:0  REJECTED:0  ERR:0 (DS API failure, keeping all {len(current)} findings)")
                confirmed = list(current)
            else:
                print(f"      CONFIRMED:{len(confirmed)}  REJECTED:{len(rejected)}  ERR:{len(cf_errors)}")
            if fp_removed > 0 and len(current) > 0:
                print(f"      FP reduction: {fp_removed}/{len(current)} ({fp_removed/len(current):.0%})")
            # With --ds, pass rejected to GLM-5.2 fix; without --ds, keep conservative safety
            passed_to_ds = confirmed + cf_errors + (rejected if use_glm else [])
            if use_glm and rejected:
                print(f"      Rejected findings passed to GLM-5.2 fix: {len(rejected)}")
            current = passed_to_ds
            summary["confirmation"] = {"confirmed": len(confirmed), "rejected": len(rejected)}

            # P15 + P5 risk mitigation: low-confidence CONFIRMED → DS Review safety net
            CONFIDENCE_FLOOR = 0.7
            low_conf_confirmed = [f for f in confirmed if getattr(f, 'confidence', 1.0) < CONFIDENCE_FLOOR]
            if low_conf_confirmed and use_glm:
                print(f"      [SAFETY] {len(low_conf_confirmed)} confirmed with confidence < {CONFIDENCE_FLOOR} → DS Review")
                summary["confirmation"]["low_confidence_routed"] = len(low_conf_confirmed)
            elif low_conf_confirmed:
                print(f"      [NOTE] {len(low_conf_confirmed)} low-confidence confirmed (use --ds for safety review)")
        except Exception as e:
            print(f"      Unavailable ({e})")
    else:
        print(f"\n[2/4] Confirmation skipped (no findings)")

    # Phase 2.5: DS Review (fallback)
    if use_glm and current:
        print(f"\n[2.5] DS Review on {len(current)} remaining...")
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
            summary["glm_fix"] = {"tp": len(tp), "fp": len(fp), "unk": len(unk)}
        except Exception as e:
            print(f"      DS unavailable ({e})")
    else:
        status = "skipped (use --ds)" if not use_glm else "skipped"
        print(f"\n[2.5] GLM-5.2 fix {status}")

    # Phase 2.6: Labs
    if use_labs:
        print(f"\n[2.6] [Labs] heuristic review...")
        try:
            from .scanner.llm_heuristic import heuristic_scan_files, format_heuristic_results
            sp = Path(path).resolve()
            py_files = list(sp.rglob("*.py")) if sp.is_dir() else ([sp] if sp.suffix == ".py" else [])
            if len(py_files) > 20:
                py_files = py_files[:20]
            file_map = {str(pf): pf.read_text(encoding="utf-8", errors="replace") for pf in py_files if pf.exists()}
            existing_by_file = {}
            for f in current:
                fpath = f.file if hasattr(f, 'file') else str(f)
                existing_by_file.setdefault(fpath, []).append({
                    'rule_id': f.rule_id if hasattr(f, 'rule_id') else '?',
                    'line': f.line if hasattr(f, 'line') else 0,
                    'message': f.message if hasattr(f, 'message') else ''
                })
            labs_findings = heuristic_scan_files(file_map, existing_by_file)
            if labs_findings:
                print(format_heuristic_results(labs_findings))
            summary["labs"] = {"files": len(file_map), "findings": len(labs_findings)}
        except Exception as e:
            print(f"      Unavailable ({e})")
    else:
        print(f"\n[2.6] Labs skipped (use --labs)")

    # Phase 3: Fix
    print(f"\n[3/4] Fixing {len(current)} findings (mode={mode})...")
    if not current:
        print("      Nothing to fix.")
        summary["fix"] = {"fixed_count": 0, "manual_count": 0, "files_changed": 0, "diff": ""}
        return summary

    fixer_input = [{"rule_id": f.rule_id, "line": f.line, "file": f.file, "snippet": f.code_snippet or ""} for f in current]
    if use_bandit:
        from .scanner.bandit_rules import map_bandit_finding
        fixer_input = [map_bandit_finding(f) for f in fixer_input]
    fix_result = fixer_run(fixer_input, mode=mode, write=write)
    print(f"      Fixed: {fix_result['fixed_count']}  Manual: {fix_result['manual_count']}  Files: {fix_result['files_changed']}")
    if fix_result.get("diff"):
        print(fix_result["diff"])
    summary["fix"] = fix_result

    # Phase 3.5: Self-validation — re-scan fixed files (P5 SecureFixAgent)
    if fix_result['fixed_count'] > 0 and fix_result.get('files'):
        print(f"\n[3.5/4] Self-validating {fix_result['files_changed']} fixed files...")
        new_issues = []
        for fpath, fcontent in fix_result['files'].items():
            try:
                from pathlib import Path as _P
                tmp = _P(fpath).parent / ('_agentguard_validate_' + _P(fpath).name)
                tmp.write_text(fcontent, encoding='utf-8')
                re_scan = _scan(str(tmp.parent), tier=tier)
                re_findings = [f for f in re_scan.findings if f.confidence >= 0.5]
                # Only flag NEW issues (line not in original fix targets)
                # Track original rule_ids that we attempted to fix (fixed + manual)
                original_rule_ids = {r.get('rule_id') for r in fix_result.get('results', [])}
                # Only flag genuinely NEW rule_ids the fixer introduced
                fresh = [f for f in re_findings if f.rule_id not in original_rule_ids]
                if fresh:
                    new_issues.extend(fresh)
                    print(f"      ISSUE: {fpath} — {len(fresh)} new finding(s) after fix")
                else:
                    print(f"      OK: {fpath}")
                tmp.unlink(missing_ok=True)
            except Exception as e:
                print(f"      SKIP: {fpath} ({e})")
        summary["self_validation"] = {
            "files_checked": fix_result['files_changed'],
            "new_issues": len(new_issues),
            "passed": len(new_issues) == 0
        }
        if new_issues:
            print(f"      WARNING: {len(new_issues)} new issues found — manual review recommended")
        else:
            print(f"      All clear — no new issues introduced")
    return summary


def cmd_pipeline(args):
    pipeline(
        path=args.path, mode=args.mode, use_glm=args.ds, write=args.write,
        use_bandit=getattr(args, "bandit", False), use_labs=getattr(args, "labs", False),
    )
