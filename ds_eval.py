import sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from agentguard.scanner.code_scanner import CodeScanner
from agentguard.scanner.llm_review import review_finding

print("=" * 60)
print("AgentGuard Pro v0.3.0 - DeepSeek Eval")
print("=" * 60)

target = Path(__file__).parent / "fixer" / "fixtures"
scanner = CodeScanner(tier="pro")
result = scanner.scan_directory(str(target))

# Filter by confidence threshold (ML-filtered)
high_conf = [f for f in result.findings if f.confidence >= 0.5]
low_conf = [f for f in result.findings if f.confidence < 0.5]

print(f"\n[1] Scan: {result.total_findings} total, {len(high_conf)} evaluated, {len(low_conf)} low-conf filtered")
print(f"    Critical:{result.critical_count}  High:{result.high_count}  Medium:{result.medium_count}  Low:{result.low_count}")
if low_conf:
    print("    [ML filtered out]:")
    for f in low_conf:
        print(f"      {f.rule_id} L{f.line}: conf={f.confidence:.2f} | {f.code_snippet[:60]}")

print(f"\n[2] DeepSeek review ({len(high_conf)} findings)...")
start = time.time()

reviewed = []
for f in high_conf:
    snippet = f.code_snippet or ""
    classification, confidence, reason = review_finding(
        rule_id=f.rule_id,
        severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
        message=f.message,
        code_snippet=snippet,
    )
    reviewed.append({
        "rule_id": f.rule_id,
        "line": f.line,
        "severity": str(f.severity),
        "classification": classification,
        "confidence": confidence,
        "reason": reason,
        "snippet": snippet[:60],
    })

elapsed = time.time() - start

tp = [r for r in reviewed if r["classification"] == "TRUE_POSITIVE"]
fp = [r for r in reviewed if r["classification"] == "FALSE_POSITIVE"]
unk = [r for r in reviewed if r["classification"] not in ("TRUE_POSITIVE", "FALSE_POSITIVE")]

print(f"\n[3] Results ({elapsed:.1f}s):")
print(f"    TRUE_POSITIVE:  {len(tp)}")
print(f"    FALSE_POSITIVE: {len(fp)}")
print(f"    UNKNOWN:        {len(unk)}")
if tp or fp:
    acc = len(tp) / (len(tp) + len(fp)) * 100
    print(f"    Accuracy: {acc:.0f}%")

print(f"\n--- Details ---")
for r in reviewed:
    tag = r["classification"][:4]
    print(f"  [{tag}] {r['rule_id']} L{r['line']}: {r['reason'][:70]} (conf={r['confidence']:.2f})")

print(f"\n[4] Conclusion:")
if len(fp) == 0:
    print("    PASS - zero false positives")
elif len(fp) <= 3:
    print(f"    OK - {len(fp)} false positives, acceptable")
else:
    print(f"    WARN - {len(fp)} false positives, needs rule tuning")
print("=" * 60)
