"""
AgentGuard ML False-Positive Filter v0.1
========================================
Lightweight ML-based confidence re-scoring for security findings.
No GPU required. Works with scikit-learn (optional) or pure-Python fallback.

Approach:
  1. Extract features from code context around each finding
  2. Re-score confidence using heuristic model (v0.1)
  3. v0.2 will add trained classifier on BigVul/Devign dataset
"""

import re
import ast
from pathlib import Path
from typing import List, Optional, Dict, Tuple

# ── Feature Extractors ──────────────────────────────────────────────

# Indicators that suggest a TRUE positive (higher confidence)
TRUE_POSITIVE_INDICATORS = [
    # Network I/O combined with dangerous function
    (r"requests\.(get|post|put)\s*\(.*\b" + r"os\.system" + r"\b", 0.3),
    (r"subprocess\.(run|Popen|call)\s*\(.*user", 0.3),
    # User input flowing directly to dangerous sink
    (r"input\s*\(.*\)\s*\n.*\b(exec|eval|os\.system)\b", 0.3),
    (r"request\.(GET|POST|args|form|json)\[.*\n.*\b(exec|eval)\b", 0.35),
    # Command injection patterns
    (r"f[\"'].*\{.*\}.*\".*os\.system", 0.25),
    # Deserialization from network
    (r"(requests|urllib|socket).*\n.*pickle\.loads?", 0.3),
    # Hardcoded secrets that look real (not placeholders)
    (r"(api_key|API_KEY|password|SECRET)\s*=\s*[\"'][A-Za-z0-9+/=]{20,}[\"']", 0.2),
]

# Indicators that suggest a FALSE positive (lower confidence)
FALSE_POSITIVE_INDICATORS = [
    # Example/tutorial code
    (r"#\s*(example|demo|tutorial|sample|illustration)", -0.3),
    (r"@example|@demo|def\s+demo_|def\s+example_|def\s+sample_", -0.25),
    # Test assertions
    (r"(assert|assertRaises|self\.assert|pytest\.raises)\b.*\b(eval|exec|os\.system|pickle)", -0.35),
    # Configuration/setup code
    (r"setup\.py|setup\.cfg|tox\.ini|conftest\.py|fixtures?", -0.3),
    # Comments explaining it's intentional
    (r"#\s*(intentional|on purpose|expected|allowed|safe|trusted)\b", -0.4),
    # Variable assignments (not actual calls)
    (r"=\s*(eval|exec)\s*$", -0.2),
    # Mock/patch
    (r"(mock|patch|MagicMock|unittest\.mock)\b", -0.3),
    # Documentation strings
    (r'""".*?\b(eval|exec|os\.system|pickle\.loads).*?"""', -0.35),
]

# Context features extracted via AST
AST_SAFETY_PATTERNS = {
    "in_try_except": (r"try\s*:", 0.15),      # Being in try/except suggests awareness
    "has_sanitization": (r"(\.strip\(\)|\.replace\(|re\.escape|shlex\.quote|sanitize)", 0.2),
    "has_input_validation": (r"(isinstance|is\s+None|==\s*None|\.isdigit\(\))", 0.15),
    "variable_named_safe": (r"(safe_|trusted_|sanitized_|validated_)", 0.2),
}


def extract_context_window(source_lines: List[str], lineno: int, window: int = 3) -> str:
    """Extract code lines around a finding for context analysis."""
    start = max(0, lineno - window - 1)
    end = min(len(source_lines), lineno + window)
    window_lines = source_lines[start:end]
    return "\n".join(window_lines)


def analyze_finding_context(
    code_snippet: str,
    filepath: str,
    lineno: int,
    source_lines: Optional[List[str]] = None,
    surrounding_context: str = "",
) -> Dict[str, float]:
    """
    Analyze the context of a finding and return confidence adjustments.
    Returns dict of {reason: adjustment}
    """
    adjustments = {}

    file_lower = filepath.lower()
    context = surrounding_context or code_snippet

    # Check true positive indicators
    for pattern, adjustment in TRUE_POSITIVE_INDICATORS:
        if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
            key = f"tp:{pattern[:30]}"
            if key not in adjustments:
                adjustments[key] = adjustment

    # Check false positive indicators
    for pattern, adjustment in FALSE_POSITIVE_INDICATORS:
        if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
            key = f"fp:{pattern[:30]}"
            if key not in adjustments:
                adjustments[key] = adjustment

    # File path heuristics
    if "/test/" in file_lower or "\\test\\" in file_lower or file_lower.startswith("test_"):
        adjustments["fp:test_file"] = -0.3

    if "/example/" in file_lower or "/demo/" in file_lower or "/sample/" in file_lower:
        adjustments["fp:example_file"] = -0.35

    if "/vendor/" in file_lower or "/third_party/" in file_lower or "/node_modules/" in file_lower:
        adjustments["fp:third_party"] = -0.5

    # AST safety patterns in context
    for feature_name, (pattern, adjustment) in AST_SAFETY_PATTERNS.items():
        if re.search(pattern, context, re.IGNORECASE):
            adjustments[f"safe:{feature_name}"] = adjustment

    # In main block? Already handled by scanner, but double-check
    if source_lines and lineno > 0:
        for i in range(max(0, lineno - 10), lineno):
            if i < len(source_lines) and "__name__" in source_lines[i] and "__main__" in source_lines[i]:
                adjustments["fp:main_block"] = -0.25
                break

    return adjustments


def rescore_confidence(
    base_confidence: float,
    adjustments: Dict[str, float],
    max_adjustment: float = 0.5,
) -> Tuple[float, List[str]]:
    """
    Apply ML-informed adjustments to a finding's confidence score.
    Returns (new_confidence, reasons)
    """
    total_adjustment = sum(adjustments.values())
    # Clamp total adjustment
    total_adjustment = max(-max_adjustment, min(max_adjustment, total_adjustment))

    new_confidence = base_confidence + total_adjustment
    new_confidence = max(0.05, min(1.0, new_confidence))  # Keep in [0.05, 1.0]

    reasons = [f"{k}: {v:+.2f}" for k, v in sorted(adjustments.items(), key=lambda x: -abs(x[1]))]

    return new_confidence, reasons


class MLFilter:
    """
    ML-based false positive filter for AgentGuard.

    Usage:
        mlf = MLFilter()
        for finding in scan_result.findings:
            new_conf, reasons = mlf.rescore(finding)
            finding.confidence = new_conf
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the ML filter.

        Args:
            model_path: Future path to a trained classifier model.
                        Currently unused (v0.1 uses heuristic model).
        """
        self.model_path = model_path
        self._rules_cache: Dict[str, bool] = {}

    def rescore(
        self,
        finding,
        source_content: Optional[str] = None,
    ) -> Tuple[float, List[str]]:
        """
        Re-score a finding's confidence.

        Args:
            finding: Finding dataclass with code_snippet, file, line, confidence
            source_content: Optional full source file content for context

        Returns:
            (new_confidence, reasons_list)
        """
        source_lines = None
        if source_content:
            source_lines = source_content.split("\n")

        context = finding.code_snippet
        if source_lines and finding.line > 0:
            context = extract_context_window(source_lines, finding.line, window=4)

        adjustments = analyze_finding_context(
            code_snippet=finding.code_snippet,
            filepath=finding.file,
            lineno=finding.line,
            source_lines=source_lines,
            surrounding_context=context,
        )

        new_conf, reasons = rescore_confidence(finding.confidence, adjustments)
        return new_conf, reasons

    def rescore_batch(
        self,
        findings: List,
        file_contents: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[float, List[str]]]:
        """
        Re-score a batch of findings.

        Args:
            findings: List of Finding objects
            file_contents: Optional dict of {filepath: content}

        Returns:
            List of (new_confidence, reasons) tuples
        """
        results = []
        for finding in findings:
            content = None
            if file_contents and finding.file in file_contents:
                content = file_contents[finding.file]
            new_conf, reasons = self.rescore(finding, content)
            results.append((new_conf, reasons))
        return results

    def filter(
        self,
        findings: List,
        min_confidence: float = 0.5,
        file_contents: Optional[Dict[str, str]] = None,
    ) -> Tuple[List, List]:
        """
        Filter findings: keep only those above min_confidence.
        Updates confidence in place.

        Returns:
            (kept_findings, filtered_out_findings)
        """
        kept = []
        filtered = []
        for finding in findings:
            new_conf, _ = self.rescore(finding, file_contents.get(finding.file) if file_contents else None)
            finding.confidence = new_conf
            if new_conf >= min_confidence:
                kept.append(finding)
            else:
                filtered.append(finding)
        return kept, filtered


# ── Training Data Generator (for future ML model) ────────────────────

def generate_training_features(
    finding,
    source_content: str,
    is_true_positive: bool,
) -> Dict:
    """
    Generate labeled training features for future ML model.
    Returns a dict of features + label.
    """
    source_lines = source_content.split("\n")
    context = extract_context_window(source_lines, finding.line)
    adjustments = analyze_finding_context(
        finding.code_snippet, finding.file, finding.line, source_lines, context
    )

    features = {
        "rule_id": finding.rule_id,
        "severity": str(finding.severity),
        "line_number": finding.line,
        "code_length": len(finding.code_snippet),
        "code_has_comment": "#" in finding.code_snippet,
        "code_has_string": '"' in finding.code_snippet or "'" in finding.code_snippet,
        "file_is_test": "test" in finding.file.lower(),
        "context_has_try": "try" in context.lower(),
        "context_has_except": "except" in context.lower(),
        "context_has_import": "import" in context.lower(),
        "context_has_def": "def " in context.lower(),
        "context_has_class": "class " in context.lower(),
        "total_adjustment": sum(adjustments.values()),
        "num_adjustments": len(adjustments),
        "label": 1 if is_true_positive else 0,
    }
    return features
