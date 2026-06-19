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
    
    from .scanner.llm_heuristic import confirm_sast_findings
    
    by_file = {}
    for f in findings:
        fpath = f.file if hasattr(f, 'file') else str(f)
        by_file.setdefault(fpath, []).append({
            'rule_id': f.rule_id if hasattr(f, 'rule_id') else '?',
            'line': f.line if hasattr(f, 'line') else 0,
            'message': f.message if hasattr(f, 'message') else '',
            'code_snippet': (f.code_snippet or '')[:120] if hasattr(f, 'code_snippet') else '',
        })
    
    confirmed, rejected, errors = [], [], []
    for fpath, flist in by_file.items():
        try:
            code = Path(fpath).read_text(encoding='utf-8', errors='replace')
        except Exception:
            errors.extend(flist)
            continue
        results = confirm_sast_findings(fpath, code, flist, use_cache=True)
        
        for r in results:
            orig = next((f for f in findings if (
                (hasattr(f, 'file') and f.file == fpath) and
                (hasattr(f, 'line') and f.line == r['line'])
            )), None)
            if orig is None:
                orig = type('F', (), flist[0])()
            if r['verdict'] == 'CONFIRMED':
                if hasattr(orig, 'confidence'):
                    orig.confidence = r['confidence']
                confirmed.append(orig)
            else:
                rejected.append(orig)
    
    return confirmed, rejected, errors


def pipeline(path=".", mode="dry-run", use_ds=False, write=False, tier="pro", use_bandit=False, use_labs=False):
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
            print(f"      CONFIRMED:{len(confirmed)}  REJECTED:{len(rejected)}  ERR:{len(cf_errors)}")
            if fp_removed > 0 and len(current) > 0:
                print(f"      FP reduction: {fp_removed}/{len(current)} ({fp_removed/len(current):.0%})")
            current = confirmed + cf_errors
            summary["confirmation"] = {"confirmed": len(confirmed), "rejected": len(rejected)}
        except Exception as e:
            print(f"      Unavailable ({e})")
    else:
        print(f"\n[2/4] Confirmation skipped (no findings)")

    # Phase 2.5: DS Review (fallback)
    if use_ds and current:
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
            summary["ds_review"] = {"tp": len(tp), "fp": len(fp), "unk": len(unk)}
        except Exception as e:
            print(f"      DS unavailable ({e})")
    else:
        status = "skipped (use --ds)" if not use_ds else "skipped"
        print(f"\n[2.5] DS review {status}")

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
    return summary


def cmd_pipeline(args):
    pipeline(
        path=args.path, mode=args.mode, use_ds=args.ds, write=args.write,
        use_bandit=getattr(args, "bandit", False), use_labs=getattr(args, "labs", False),
    )
