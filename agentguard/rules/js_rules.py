"""
AgentGuard JavaScript/TypeScript Security Rules
================================================
"""
from typing import List
from .python_rules import Rule, Severity

JS_RULES: List[Rule] = [
    Rule(
        rule_id="JS001", name="eval-used",
        severity=Severity.CRITICAL,
        description="Use of eval() allows arbitrary code execution.",
        cwe="CWE-95",
        patterns=[r"\beval\s*\("],
        fix="Remove eval(). Use JSON.parse() for data.",
        category="injection",
    ),
    Rule(
        rule_id="JS002", name="new-function-injection",
        severity=Severity.CRITICAL,
        description="new Function() with dynamic string allows code injection.",
        cwe="CWE-95",
        patterns=[r"new\s+Function\s*\("],
        fix="Avoid new Function() with user input.",
        category="injection",
    ),
    Rule(
        rule_id="JS003", name="child-process-exec",
        severity=Severity.CRITICAL,
        description="child_process.exec() with string is vulnerable to command injection.",
        cwe="CWE-78",
        patterns=[r"child_process\.exec\s*\("],
        fix="Use child_process.execFile() or spawn() with array arguments.",
        category="injection",
    ),
    Rule(
        rule_id="JS010", name="innerHTML-assignment",
        severity=Severity.HIGH,
        description="innerHTML assignment can lead to XSS.",
        cwe="CWE-79",
        patterns=[r"\.innerHTML\s*="],
        fix="Use textContent or sanitize HTML with DOMPurify.",
        category="xss",
    ),
    Rule(
        rule_id="JS011", name="dangerouslySetInnerHTML",
        severity=Severity.HIGH,
        description="React dangerouslySetInnerHTML can cause XSS.",
        cwe="CWE-79",
        patterns=[r"dangerouslySetInnerHTML"],
        fix="Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML.",
        category="xss",
    ),
    Rule(
        rule_id="JS012", name="document-write",
        severity=Severity.HIGH,
        description="document.write() can lead to XSS.",
        cwe="CWE-79",
        patterns=[r"document\.write\s*\("],
        fix="Use DOM manipulation methods instead of document.write().",
        category="xss",
    ),
    Rule(
        rule_id="JS020", name="sql-injection",
        severity=Severity.CRITICAL,
        description="SQL query with string concatenation, vulnerable to SQL injection.",
        cwe="CWE-89",
        patterns=[r"\.query\s*\(.*SELECT.*\+", r"\.execute\s*\(.*SELECT.*\+"],
        fix="Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId])",
        category="injection",
    ),
    Rule(
        rule_id="JS030", name="hardcoded-password",
        severity=Severity.CRITICAL,
        description="Hardcoded password or API key in source code.",
        cwe="CWE-798",
        patterns=[r"(?:password|passwd|pwd)\s*[:=]\s*\S{4,}", r"(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*\S{20,}"],
        fix="Load credentials from environment variables: process.env.PASSWORD",
        category="secrets",
    ),
    Rule(
        rule_id="JS040", name="weak-hash-md5",
        severity=Severity.HIGH,
        description="MD5 is cryptographically broken.",
        cwe="CWE-327",
        patterns=[r"crypto\.createHash\s*\(\s*md5"],
        fix="Use SHA-256: crypto.createHash('sha256')",
        category="crypto",
    ),
    Rule(
        rule_id="JS041", name="weak-hash-sha1",
        severity=Severity.HIGH,
        description="SHA-1 is vulnerable to collision attacks.",
        cwe="CWE-327",
        patterns=[r"crypto\.createHash\s*\(\s*sha1"],
        fix="Use SHA-256: crypto.createHash('sha256')",
        category="crypto",
    ),
    Rule(
        rule_id="JS050", name="ssrf-fetch",
        severity=Severity.HIGH,
        description="User-controlled URL passed to fetch() enables SSRF.",
        cwe="CWE-918",
        patterns=[r"fetch\s*\(.*\$\{", r"fetch\s*\(.*\+"],
        fix="Validate and restrict URLs before passing to fetch().",
        category="network",
    ),
    Rule(
        rule_id="JS060", name="ssl-verification-disabled",
        severity=Severity.HIGH,
        description="SSL certificate verification disabled.",
        cwe="CWE-295",
        patterns=[r"rejectUnauthorized\s*:\s*false"],
        fix="Never disable SSL verification.",
        category="network",
    ),
    Rule(
        rule_id="JS070", name="prototype-pollution",
        severity=Severity.HIGH,
        description="Prototype pollution risk via __proto__.",
        cwe="CWE-1321",
        patterns=[r"__proto__"],
        fix="Use Object.create(null) or sanitize keys.",
        category="injection",
    ),
    Rule(
        rule_id="JS080", name="debug-enabled",
        severity=Severity.LOW,
        description="Debug mode enabled can leak sensitive information.",
        cwe="CWE-489",
        patterns=[r"NODE_ENV\s*===?\s*development"],
        fix="Disable debug mode in production.",
        category="config",
    ),
]

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def get_js_rules(tier: str = "free") -> List[Rule]:
    if tier == "pro":
        return JS_RULES
    return JS_RULES[:10]
