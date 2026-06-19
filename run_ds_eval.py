"""DS Evaluation: Phase 0 + Phase 1 combined report."""
import json, sys, io, time
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

ROOT = Path(__file__).parent
FIXTURES = ROOT / "tests" / "fixtures" / "heuristic"
SRC = ROOT / "agentguard"
EVAL_DIR = ROOT / "docs" / "eval"
EVAL_DIR.mkdir(parents=True, exist_ok=True)

from agentguard.scanner.code_scanner import CodeScanner
from agentguard.scanner.llm_review import review_finding
from agentguard.scanner.llm_heuristic import confirm_sast_findings, heuristic_scan_multi_agent

def scan(path, label):
    s = CodeScanner(tier="pro")
    r = s.scan_directory(str(Path(path).resolve()))
    print(f"  {label}: {r.files_scanned} files, {r.total_findings} findings ({r.critical_count}C/{r.high_count}H/{r.medium_count}M/{r.low_count}L)")
    return {"label": label, "files": r.files_scanned, "total": r.total_findings,
            "C": r.critical_count, "H": r.high_count, "M": r.medium_count, "L": r.low_count,
            "findings": [{"rule_id": f.rule_id, "file": f.file, "line": f.line,
                          "severity": str(f.severity), "message": f.message,
                          "snippet": (f.code_snippet or "")[:80]} for f in r.findings]}

def ds_review(findings, max_n=20):
    tp, fp, unk, err = [], [], [], 0
    for f in findings[:max_n]:
        try:
            c, conf, reason = review_finding(f["rule_id"], f["severity"], f["message"], f.get("snippet", ""))
            e = {**f, "ds_verdict": c, "ds_conf": conf, "ds_reason": reason}
            (tp if c == "TRUE_POSITIVE" else fp if c == "FALSE_POSITIVE" else unk).append(e)
        except Exception:
            err += 1
        time.sleep(0.05)
    return {"tp": len(tp), "fp": len(fp), "unk": len(unk), "errors": err, "items": tp + unk}

def confirm(tp_items, label):
    if not tp_items:
        return {"label": label, "reviewed": 0, "confirmed": 0, "rejected": 0}
    by_file = {}
    for f in tp_items:
        by_file.setdefault(f["file"], []).append(f)
    results = []
    for fp, fl in by_file.items():
        try:
            code = Path(fp).read_text(encoding="utf-8", errors="replace")
        except:
            continue
        results.extend(confirm_sast_findings(fp, code, fl, use_cache=False))
    c = sum(1 for r in results if r["verdict"] == "CONFIRMED")
    r = sum(1 for r in results if r["verdict"] == "REJECTED")
    return {"label": label, "reviewed": len(tp_items), "confirmed": c, "rejected": r,
            "precision": c / max(len(tp_items), 1)}

# ===== PHASE 0 =====
print("=" * 60)
print("PHASE 0: Rule Baseline")
print("=" * 60)

p0_fix = scan(FIXTURES, "Test Fixtures")
p0_self = scan(SRC, "AgentGuard self-scan")

print("\n" + "=" * 60)
print("PHASE 0.5: DS Review on findings")
print("=" * 60)
ds_fix = ds_review(p0_fix["findings"])
ds_self = ds_review(p0_self["findings"])
print(f"  Fixtures: TP={ds_fix['tp']} FP={ds_fix['fp']} UNK={ds_fix['unk']}")
print(f"  Self:     TP={ds_self['tp']} FP={ds_self['fp']} UNK={ds_self['unk']}")

print("\n" + "=" * 60)
print("PHASE 1: Confirmation Agent")
print("=" * 60)
c_fix = confirm(ds_fix["items"], "Fixtures")
c_self = confirm(ds_self["items"], "Self")
print(f"  Fixtures: {c_fix['reviewed']} → {c_fix['confirmed']} confirmed, {c_fix['rejected']} rejected")
print(f"  Self:     {c_self['reviewed']} → {c_self['confirmed']} confirmed, {c_self['rejected']} rejected")

print("\n" + "=" * 60)
print("PHASE 1b: Heuristic Discovery (known vulns)")
print("=" * 60)
h_results = {}
for f in sorted(FIXTURES.glob("test_*.py")):
    code = f.read_text(encoding="utf-8")
    findings = heuristic_scan_multi_agent(str(f), code, [], use_cache=True)
    h_results[f.name] = {"total": len(findings),
        "types": list(set(ff.risk_type for ff in findings)),
        "items": [{"risk_type": ff.risk_type, "L": f"{ff.line_start}-{ff.line_end}", "conf": ff.confidence} for ff in findings]}
    print(f"  {'✅' if len(findings) > 0 else '❌'} {f.name}: {len(findings)}")

# ===== SAVE =====
report = {
    "date": "2026-06-20",
    "model": "deepseek-v4-flash @ 127.0.0.1:57321",
    "supervisor": "军师",
    "phase0": {"fixtures": {k: v for k, v in p0_fix.items() if k != "findings"}, "self": {k: v for k, v in p0_self.items() if k != "findings"}},
    "phase0_ds_review": {"fixtures": {k: v for k, v in ds_fix.items() if k != "items"}, "self": {k: v for k, v in ds_self.items() if k != "items"}},
    "phase1_confirmation": {"fixtures": c_fix, "self": c_self},
    "phase1_heuristic": h_results,
}
out = EVAL_DIR / "phase-0-1-20260620.json"
out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"\n{'=' * 60}")
print("REPORT SAVED")
print(f"{'=' * 60}")
print(f"  {out}")
print(f"  Phase 0: {p0_fix['total'] + p0_self['total']} findings (rules)")
print(f"  Phase 0.5: DS reduced to {ds_fix['tp'] + ds_self['tp']} TP ({ds_fix['fp'] + ds_self['fp']} FP removed)")
print(f"  Phase 1: Confirmation precision {c_fix.get('precision',0):.1%} (fixtures) / {c_self.get('precision',0):.1%} (self)")
detected = sum(1 for v in h_results.values() if v["total"] > 0)
print(f"  Phase 1b: Heuristic {detected}/{len(h_results)} files detected")
