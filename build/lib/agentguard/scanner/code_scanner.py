"""
AgentGuard Code Scanner v0.2
=============================
Pattern-based + AST-aware + Context-filtered security scanner.

v0.2: Context-aware false positive reduction
  - Test file confidence reduction (50%)
  - Suppress comments (# agentguard: ignore, # nosec)
  - __name__ == "__main__" context awareness
"""

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

from ..rules.python_rules import Rule, Severity, PYTHON_RULES, get_rules
from ..ignore_config import IgnoreConfig
from ..rules.js_rules import JS_RULES, JS_EXTENSIONS, get_js_rules


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    code_snippet: str = ""
    fix: str = ""
    confidence: float = 1.0


@dataclass
class ScanResult:
    path: str
    files_scanned: int
    total_lines: int
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    false_positives_filtered: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL and f.confidence >= 0.5)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH and f.confidence >= 0.5)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0


class CodeScanner:
    PYTHON_EXTS = {".py", ".pyw", ".pyi"}
    SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules",
                 ".tox", ".eggs", "dist", "build", ".mypy_cache", ".pytest_cache"}
    TEST_PATH_PATTERNS = ["/test/", "\\test\\", "/tests/", "\\tests\\",
                          "test_", "_test.py"]
    SUPPRESS_COMMENTS = ["agentguard: ignore", "nosec", "agentguard: skip"]
    # Files that are rule definitions themselves — scanning them creates self-referential FPs
    SKIP_FILES = {"python_rules.py", "bandit_rules.py"}
    MAX_FILE_SIZE = 1_024_000

    def __init__(self, tier: str = "free", max_files: int = 100):
        self.tier = tier
        self.rules = get_rules(tier)
        self.max_files = max_files
        self.use_ml = True  # Enable ML false-positive filter
        self._ml_filter = None
        self._ignore_config = IgnoreConfig.from_file()
        self.use_llm = False  # Enable LLM secondary review (requires DS API)
        self._llm_reviewer = None
        self._compiled: List[tuple] = []
        for rule in self.rules:
            for pat in rule.patterns:
                try:
                    self._compiled.append((re.compile(pat), rule))
                except re.error:
                    pass

    def _is_test_file(self, filepath: Path) -> bool:
        s = str(filepath).replace("\\", "/")
        return any(p in s for p in self.TEST_PATH_PATTERNS)

    def _is_suppressed(self, line_text: str) -> bool:
        lower = line_text.lower()
        return any(c in lower for c in self.SUPPRESS_COMMENTS)

    def _is_main_block(self, lines: List[str], lineno: int) -> bool:
        """Check if code at lineno is inside if __name__ == '__main__' block."""
        indent = 0
        if 0 < lineno <= len(lines):
            line = lines[lineno - 1]
            indent = len(line) - len(line.lstrip())
        for i in range(lineno - 2, -1, -1):
            l = lines[i].strip()
            li = len(lines[i]) - len(lines[i].lstrip())
            if li < indent and l:
                if "__name__" in l and "__main__" in l:
                    return True
                break
        return False

    def scan_directory(self, path: str, files: Optional[List[str]] = None) -> ScanResult:
        result = ScanResult(path=path, files_scanned=0, total_lines=0)
        if files:
            target_files = [Path(p) for p in files if Path(p).exists()]
        else:
            target_files = self._collect_files(Path(path))
        if len(target_files) > self.max_files:
            result.errors.append(
                f"Free tier limit: {self.max_files} files. Found {len(target_files)}. Upgrade to Pro.")
            target_files = target_files[:self.max_files]
        for filepath in target_files:
            try:
                result.files_scanned += 1
                file_findings = self._scan_file(filepath)
                result.findings.extend(file_findings)
                result.total_lines += self._count_lines(filepath)
            except Exception as e:
                result.errors.append(f"Error scanning {filepath}: {e}")
        # Apply ignore config — filter out ignored findings
        if self._ignore_config and self._ignore_config.file_patterns or self._ignore_config and self._ignore_config.rule_ids or self._ignore_config and self._ignore_config.file_rules:
            before = len(result.findings)
            result.findings = [f for f in result.findings 
                             if not self._ignore_config.should_ignore(f.file, f.rule_id)]
            ignored = before - len(result.findings)
            if ignored:
                result.errors.append(f"{ignored} findings ignored by .agentguard-ignore")

        result.false_positives_filtered = sum(1 for f in result.findings if f.confidence < 0.5)

        # ML heuristic confidence rescoring
        if self.use_ml and result.findings:
            try:
                from .ml_filter import MLFilter
                if self._ml_filter is None:
                    self._ml_filter = MLFilter()
                for finding in result.findings:
                    new_conf, reasons = self._ml_filter.rescore(finding)
                    finding.confidence = new_conf
            except ImportError:
                pass

        # LLM secondary review (GLM-5.2 API)
        if self.use_llm and result.findings:
            try:
                from .llm_review import LLMReviewer
                if self._llm_reviewer is None:
                    self._llm_reviewer = LLMReviewer()
                self._llm_reviewer.apply_review(result.findings)
            except ImportError:
                pass

        # P4: GLM-5.2 deep scan (Pro tier — finds what rules miss)
        if self.tier == "pro" and getattr(self, 'use_llm_deep', False):
            try:
                deep_findings = self._glm_deep_scan(path)
                result.findings.extend(deep_findings)
            except Exception as e:
                result.errors.append(f"GLM-5.2 deep scan error: {e}")

        # Recalculate filtered count after ML/LLM
        # Apply ignore config — filter out ignored findings
        if self._ignore_config and self._ignore_config.file_patterns or self._ignore_config and self._ignore_config.rule_ids or self._ignore_config and self._ignore_config.file_rules:
            before = len(result.findings)
            result.findings = [f for f in result.findings 
                             if not self._ignore_config.should_ignore(f.file, f.rule_id)]
            ignored = before - len(result.findings)
            if ignored:
                result.errors.append(f"{ignored} findings ignored by .agentguard-ignore")

        result.false_positives_filtered = sum(1 for f in result.findings if f.confidence < 0.5)
        return result

    def _collect_files(self, root: Path) -> List[Path]:
        ALL_EXTS = self.PYTHON_EXTS | JS_EXTENSIONS
        # Single file: return directly
        if root.is_file() and root.suffix in ALL_EXTS:
            return [root]
        files = []
        for entry in root.rglob("*"):
            if entry.is_file() and entry.suffix in ALL_EXTS:
                parts = set(entry.parts)
                if not parts & self.SKIP_DIRS:
                    if entry.name in self.SKIP_FILES:
                        continue  # Rule definition files — self-referential FPs
                    if entry.stat().st_size <= self.MAX_FILE_SIZE:
                        files.append(entry)
        return files

    def _scan_file(self, filepath: Path) -> List[Finding]:
        findings = []
        is_test = self._is_test_file(filepath)
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            lines = source.splitlines()
        except Exception:
            return findings

        # Route by language: JS/TS files use JS rules, Python uses Python rules
        if filepath.suffix in JS_EXTENSIONS:
            findings.extend(self._pattern_scan_js(filepath, source, lines, is_test))
        else:
            findings.extend(self._pattern_scan(filepath, source, lines, is_test))
            findings.extend(self._ast_scan(filepath, source, lines, is_test))
        findings.extend(self._file_checks(filepath, source))

        # Deduplicate: pattern scan + AST scan may flag same (rule_id, line)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.rule_id, f.line)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
        return findings

    def _pattern_scan_js(self, filepath, source, lines, is_test):
        """Pattern scan for JavaScript/TypeScript files using JS rules."""
        findings = []
        js_rules = get_js_rules(self.tier)
        compiled = []
        for rule in js_rules:
            for pat in rule.patterns:
                compiled.append((re.compile(pat), rule))
        for regex, rule in compiled:
            for match in regex.finditer(source):
                pos = match.start()
                line_no = source.count("\n", 0, pos) + 1
                col = pos - (source.rfind("\n", 0, pos) + 1)
                snippet = ""
                if 0 < line_no <= len(lines):
                    snippet = lines[line_no - 1].strip()[:120]
                    if self._is_suppressed(lines[line_no - 1]):
                        continue
                confidence = 1.0
                if is_test:
                    confidence = 0.5
                findings.append(Finding(
                    rule_id=rule.rule_id, severity=rule.severity,
                    file=str(filepath), line=line_no, column=max(0, col),
                    message=rule.description, code_snippet=snippet,
                    fix=rule.fix, confidence=confidence))
        return findings

    def _pattern_scan(self, filepath, source, lines, is_test):
        findings = []
        # LLM-specific rules only apply to files that import LLM libraries
        _LLM_RULES = {"PY050", "PY051", "PY052"}
        _LLM_KEYWORDS = ("openai", "anthropic", "langchain", "transformers",
                         "chat.completion", "chat_completion", "zhipuai", "glm-",
                         "ollama", "llama-cpp", "from langchain", "import openai",
                         "import anthropic", "ChatCompletion", "messages.*role.*assistant")
        has_llm = any(kw in source.lower() for kw in _LLM_KEYWORDS)

        for regex, rule in self._compiled:
            if rule.rule_id in _LLM_RULES and not has_llm:
                continue
            for match in regex.finditer(source):
                pos = match.start()
                line_no = source.count("\n", 0, pos) + 1
                col = pos - (source.rfind("\n", 0, pos) + 1)
                snippet = ""
                if 0 < line_no <= len(lines):
                    snippet = lines[line_no - 1].strip()[:120]
                    if self._is_suppressed(lines[line_no - 1]):
                        continue
                confidence = 1.0
                if is_test:
                    confidence = 0.5
                if self._is_main_block(lines, line_no):
                    confidence = min(confidence, 0.6)
                findings.append(Finding(
                    rule_id=rule.rule_id, severity=rule.severity,
                    file=str(filepath), line=line_no, column=max(0, col),
                    message=rule.description, code_snippet=snippet,
                    fix=rule.fix, confidence=confidence))
        return findings

    def _ast_scan(self, filepath, source, lines, is_test):
        findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings
        visitor = _SecurityVisitor(filepath, lines, self.rules, is_test, self)
        visitor.visit(tree)
        return visitor.findings

    def _file_checks(self, filepath, source):
        findings = []
        if filepath.name == ".env" or filepath.suffix == ".env":
            findings.append(Finding(rule_id="PY022", severity=Severity.HIGH,
                file=str(filepath), line=0, column=0,
                message=".env file should not be committed.",
                fix="Add .env to .gitignore."))
        if os.name != "nt":
            try:
                if filepath.stat().st_mode & 0o002:
                    findings.append(Finding(rule_id="PY099", severity=Severity.MEDIUM,
                        file=str(filepath), line=0, column=0,
                        message="File is world-writable.",
                        fix="chmod o-w " + str(filepath)))
            except Exception:
                pass
        return findings

    @staticmethod
    def _count_lines(filepath):
        try:
            return sum(1 for _ in open(filepath, encoding="utf-8", errors="replace"))
        except Exception:
            return 0


class _SecurityVisitor(ast.NodeVisitor):
    def __init__(self, filepath, lines, rules, is_test, scanner):
        self.filepath = filepath
        self.lines = lines
        self.rules = {r.rule_id: r for r in rules}
        self.is_test = is_test
        self.scanner = scanner
        self.findings: List[Finding] = []

    def _add_finding(self, rule_id, node, extra_msg=""):
        rule = self.rules.get(rule_id)
        if not rule:
            return
        lineno = node.lineno or 0
        if 0 < lineno <= len(self.lines):
            if self.scanner._is_suppressed(self.lines[lineno - 1]):
                return
        msg = rule.description
        if extra_msg:
            msg += " " + extra_msg
        snippet = ""
        if lineno and 0 < lineno <= len(self.lines):
            snippet = self.lines[lineno - 1].strip()[:120]
        confidence = 1.0
        if self.is_test:
            confidence = 0.5
        if self.scanner._is_main_block(self.lines, lineno):
            confidence = min(confidence, 0.6)
        self.findings.append(Finding(
            rule_id=rule_id, severity=rule.severity,
            file=str(self.filepath), line=lineno,
            column=node.col_offset or 0, message=msg,
            code_snippet=snippet, fix=rule.fix, confidence=confidence))

    def _has_llm_context(self):
        """Check if this file has LLM/AI context (imports, API calls)."""
        _LLM_KW = ("openai", "anthropic", "langchain", "transformers",
                    "chat_completion", "zhipuai", "glm-", "ollama",
                    "import openai", "import anthropic", "ChatCompletion")
        source_low = "\n".join(self.lines).lower()
        return any(kw in source_low for kw in _LLM_KW)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self._add_finding("PY001", node)
            elif node.func.id == "exec":
                self._add_finding("PY002", node)
        if (isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name)):
            nv, na = node.func.value.id, node.func.attr
            if nv == "os" and na == "system":
                self._add_finding("PY003", node)
            elif nv == "pickle" and na in ("load", "loads", "Unpickler"):
                self._add_finding("PY005", node)
            elif nv == "yaml" and na in ("load", "full_load"):
                self._add_finding("PY006", node)
            elif nv == "marshal" and na in ("load", "loads"):
                self._add_finding("PY007", node)
        self.generic_visit(node)

    def visit_While(self, node):
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            has_exit = any(isinstance(n, (ast.Break, ast.Return)) for n in ast.walk(node))
            if not has_exit:
                self._add_finding("PY052", node, "No visible exit condition.")
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        for value in node.values:
            if isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                if value.value.id.lower() in ("input", "user_input", "query", "prompt"):
                    # Only flag if this file has LLM context
                    if not self._has_llm_context():
                        continue
                    self._add_finding("PY050", node,
                        f"User input '{value.value.id}' in f-string.")
        self.generic_visit(node)
