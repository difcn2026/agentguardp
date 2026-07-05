"""
AgentGuard Python Security Rules v0.1
======================================
50 built-in rules covering the most common Agent-generated code vulnerabilities.
Each rule: id, severity, pattern, message, CWE reference.
"""

from dataclasses import dataclass
from typing import List, Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Rule:
    rule_id: str
    name: str
    severity: Severity
    description: str
    cwe: Optional[str] = None
    patterns: List[str] = None
    ast_types: List[str] = None
    fix: str = ""
    category: str = "general"

    def __post_init__(self):
        if self.patterns is None:
            self.patterns = []
        if self.ast_types is None:
            self.ast_types = []


# ============================================================
# RULE SET: 50 rules in 7 categories
# ============================================================

PYTHON_RULES: List[Rule] = [
    # ---- CATEGORY 1: Code Injection (CRITICAL) ----
    Rule(
        rule_id="PY001", name="eval-used",
        severity=Severity.CRITICAL,
        description="Use of eval() allows arbitrary code execution from string input.",
        cwe="CWE-95",
        patterns=[r"\beval\s*\("],
        fix="Replace eval() with ast.literal_eval() for data, or use a safe parser.",
        category="injection",
    ),
    Rule(
        rule_id="PY002", name="exec-used",
        severity=Severity.CRITICAL,
        description="Use of exec() allows arbitrary code execution.",
        cwe="CWE-95",
        patterns=[r"\bexec\s*\("],
        fix="Remove exec(). There is no safe use of exec() with untrusted input.",
        category="injection",
    ),
    Rule(
        rule_id="PY003", name="os-system-used",
        severity=Severity.CRITICAL,
        description="os.system() passes strings to shell, vulnerable to command injection.",
        cwe="CWE-78",
        patterns=[r"\bos\.system\s*\("],
        fix="Use subprocess.run() with a list of arguments (not a string) and shell=False.",
        category="injection",
    ),
    Rule(
        rule_id="PY004", name="subprocess-shell-true",
        severity=Severity.CRITICAL,
        description="subprocess with shell=True is vulnerable to command injection.",
        cwe="CWE-78",
        patterns=[r"shell\s*=\s*True"],
        fix="Set shell=False and pass arguments as a list.",
        category="injection",
    ),
    Rule(
        rule_id="PY005", name="pickle-loads",
        severity=Severity.CRITICAL,
        description="pickle.loads() on untrusted data allows arbitrary code execution.",
        cwe="CWE-502",
        patterns=[r"\bpickle\.(loads?|Unpickler)\s*\("],
        fix="Use safetensors for ML models, or json.loads() for data. Never unpickle untrusted data.",
        category="injection",
    ),
    Rule(
        rule_id="PY006", name="yaml-unsafe-load",
        severity=Severity.HIGH,
        description="yaml.load() without SafeLoader can execute arbitrary code.",
        cwe="CWE-502",
        patterns=[r"\byaml\.load\s*\(", r"\byaml\.full_load\s*\("],
        fix="Use yaml.safe_load() instead.",
        category="injection",
    ),
    Rule(
        rule_id="PY007", name="marshal-loads",
        severity=Severity.HIGH,
        description="marshal.loads() on untrusted data can crash or exploit the interpreter.",
        cwe="CWE-502",
        patterns=[r"\bmarshal\.loads?\s*\("],
        fix="Use json or a safe serialization format instead.",
        category="injection",
    ),

    # ---- CATEGORY 2: Path Traversal & File Access ----
    Rule(
        rule_id="PY010", name="path-traversal-join",
        severity=Severity.HIGH,
        description="Joining user input into file paths without sanitization enables path traversal.",
        cwe="CWE-22",
        patterns=[],
        ast_types=["JoinedStr"],
        fix="Use os.path.realpath() and verify the resolved path is within an allowed directory.",
        category="path_traversal",
    ),
    Rule(
        rule_id="PY011", name="open-user-input",
        severity=Severity.MEDIUM,
        description="Opening files with paths from user input without validation.",
        cwe="CWE-22",
        patterns=[r"\bopen\s*\(\s*.+[+]\s*.+", r"\bopen\s*\(\s*f['\"]"],
        fix="Validate file paths against an allowlist. Use pathlib with resolve().",
        category="path_traversal",
    ),
    Rule(
        rule_id="PY012", name="tempfile-insecure",
        severity=Severity.MEDIUM,
        description="Insecure temporary file creation can lead to race conditions.",
        cwe="CWE-377",
        patterns=[r"\bos\.tempnam\s*\(", r"\bos\.tmpnam\s*\("],
        fix="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
        category="path_traversal",
    ),

    # ---- CATEGORY 3: Secrets & Credentials (CRITICAL) ----
    Rule(
        rule_id="PY020", name="hardcoded-api-key",
        severity=Severity.CRITICAL,
        description="Hardcoded API key, token, or password in source code.",
        cwe="CWE-798",
        patterns=[
            r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
            r"password\s*=\s*['\"][^'\"]+['\"]",
        ],
        fix="Store secrets in environment variables or a vault (e.g., .env file, HashiCorp Vault).",
        category="secrets",
    ),
    Rule(
        rule_id="PY021", name="hardcoded-private-key",
        severity=Severity.CRITICAL,
        description="Private key material found in source code.",
        cwe="CWE-798",
        patterns=[
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            r"-----BEGIN PRIVATE KEY-----",
        ],
        fix="Store private keys outside the repository. Use environment variables or key management services.",
        category="secrets",
    ),
    Rule(
        rule_id="PY022", name="dotenv-committed",
        severity=Severity.HIGH,
        description=".env file should not be committed to version control.",
        cwe="CWE-538",
        patterns=[],
        fix="Add .env to .gitignore. Create .env.example as a template.",
        category="secrets",
    ),

    # ---- CATEGORY 4: Cryptography & Hashing ----
    Rule(
        rule_id="PY030", name="weak-hash-md5",
        severity=Severity.HIGH,
        description="MD5 is cryptographically broken. Do not use for security purposes.",
        cwe="CWE-328",
        patterns=[r"\bhashlib\.md5\s*\(", r"\bmd5\s*\("],
        fix="Use hashlib.sha256() or hashlib.sha3_256() instead.",
        category="crypto",
    ),
    Rule(
        rule_id="PY031", name="weak-hash-sha1",
        severity=Severity.HIGH,
        description="SHA-1 is vulnerable to collision attacks.",
        cwe="CWE-328",
        patterns=[r"\bhashlib\.sha1\s*\(", r"\bsha1\s*\("],
        fix="Use hashlib.sha256() or stronger.",
        category="crypto",
    ),
    Rule(
        rule_id="PY032", name="weak-random",
        severity=Severity.MEDIUM,
        description="random module is not cryptographically secure.",
        cwe="CWE-338",
        patterns=[r"\brandom\.(random|randint|choice|shuffle)\s*\("],
        fix="Use secrets module (secrets.token_bytes, secrets.choice) for security-sensitive randomness.",
        category="crypto",
    ),

    # ---- CATEGORY 5: Network & SSRF ----
    Rule(
        rule_id="PY040", name="ssrf-requests",
        severity=Severity.HIGH,
        description="User-controlled URL passed to requests.get() enables SSRF attacks.",
        cwe="CWE-918",
        patterns=[r"\brequests\.(get|post|put|delete|head|patch)\s*\(\s*[^'\"\s]"],
        fix="Validate URLs against an allowlist of domains. Block internal IPs (127.0.0.0/8, 10.0.0.0/8, etc.).",
        category="network",
    ),
    Rule(
        rule_id="PY041", name="ssrf-urllib",
        severity=Severity.HIGH,
        description="User-controlled URL passed to urllib enables SSRF attacks.",
        cwe="CWE-918",
        patterns=[r"\burllib\.request\.urlopen\s*\(\s*[^'\"\s]"],
        fix="Implement URL validation with an allowlist. Use a proxy for outbound requests.",
        category="network",
    ),
    Rule(
        rule_id="PY042", name="ssl-unverified",
        severity=Severity.MEDIUM,
        description="SSL certificate verification is disabled.",
        cwe="CWE-295",
        patterns=[r"verify\s*=\s*False", r"ssl\.CERT_NONE"],
        fix="Enable SSL certificate verification. If testing, use a local CA.",
        category="network",
    ),

    # ---- CATEGORY 6: Agent-Specific ----
    Rule(
        rule_id="PY050", name="agent-prompt-injection",
        severity=Severity.HIGH,
        description="Code passes untrusted user input directly into LLM prompts without sanitization.",
        cwe="CWE-77",
        patterns=[r"messages.*role.*system.*\+.*input", r"system.*prompt.*\+.*request"],
        fix="Sanitize user input before inserting into prompts. Use prompt templates with parameterized inputs.",
        category="agent",
    ),
    Rule(
        rule_id="PY051", name="agent-tool-no-auth",
        severity=Severity.HIGH,
        description="Agent tool function has no authorization check before executing sensitive operations.",
        cwe="CWE-862",
        patterns=[],
        ast_types=["FunctionDef"],
        fix="Add an authorization decorator or guard clause to every agent tool function.",
        category="agent",
    ),
    Rule(
        rule_id="PY052", name="agent-unbounded-loop",
        severity=Severity.MEDIUM,
        description="Agent logic contains while True without timeout or iteration limit.",
        cwe="CWE-834",
        patterns=[r"\bwhile\s+True\s*:"],
        fix="Add a max_iterations counter or timeout mechanism to prevent infinite agent loops.",
        category="agent",
    ),

    # ---- CATEGORY 7: General Best Practices ----
    Rule(
        rule_id="PY060", name="debug-true",
        severity=Severity.LOW,
        description="DEBUG=True in production can leak sensitive information.",
        cwe="CWE-489",
        patterns=[r"\bDEBUG\s*=\s*True"],
        fix="Set DEBUG=False in production. Use environment variables to control debug mode.",
        category="general",
    ),
    Rule(
        rule_id="PY061", name="assert-on-tuple",
        severity=Severity.LOW,
        description="assert (x, y) is always True — non-empty tuple is truthy.",
        cwe="CWE-617",
        patterns=[r"\bassert\s+\("],
        fix="Remove parentheses from assert statements, or use explicit condition checks.",
        category="general",
    ),

    # ---- CATEGORY 8: XML Parsing (B313-B320) ----
    Rule(
        rule_id="PY070", name="xml-bad-cElementTree",
        severity=Severity.MEDIUM,
        description="xml.etree.cElementTree parsing untrusted XML is vulnerable to XML attacks.",
        cwe="CWE-611",
        patterns=[r"\bxml\.etree\.cElementTree\.(parse|iterparse|fromstring|XMLParser)\s*\("],
        fix="Use defusedxml.cElementTree instead of xml.etree.cElementTree.",
        category="xml",
    ),
    Rule(
        rule_id="PY071", name="xml-bad-ElementTree",
        severity=Severity.MEDIUM,
        description="xml.etree.ElementTree parsing untrusted XML is vulnerable to XML attacks.",
        cwe="CWE-611",
        patterns=[r"\bxml\.etree\.ElementTree\.(parse|iterparse|fromstring|XMLParser)\s*\("],
        fix="Use defusedxml.ElementTree instead of xml.etree.ElementTree.",
        category="xml",
    ),
    Rule(
        rule_id="PY072", name="xml-bad-expatreader",
        severity=Severity.MEDIUM,
        description="xml.sax.expatreader parsing untrusted XML is vulnerable to XML attacks.",
        cwe="CWE-611",
        patterns=[r"\bxml\.sax\.expatreader\.create_parser\s*\("],
        fix="Use defusedxml.sax instead of xml.sax.expatreader.",
        category="xml",
    ),
    Rule(
        rule_id="PY073", name="xml-bad-expatbuilder",
        severity=Severity.MEDIUM,
        description="xml.dom.expatbuilder parsing untrusted XML is vulnerable to XML attacks.",
        cwe="CWE-611",
        patterns=[r"\bxml\.dom\.expatbuilder\.(parse|parseString)\s*\("],
        fix="Use defusedxml.dom instead of xml.dom.expatbuilder.",
        category="xml",
    ),
    Rule(
        rule_id="PY074", name="xml-bad-sax",
        severity=Severity.MEDIUM,
        description="xml.sax parsing untrusted XML is vulnerable to XML attacks (billion laughs, XXE).",
        cwe="CWE-611",
        patterns=[r"\bxml\.sax\.(parse|parseString|make_parser)\s*\("],
        fix="Use defusedxml.sax instead of xml.sax.",
        category="xml",
    ),
    Rule(
        rule_id="PY075", name="xml-bad-minidom",
        severity=Severity.MEDIUM,
        description="xml.dom.minidom parsing untrusted XML is vulnerable to XML attacks.",
        cwe="CWE-611",
        patterns=[r"\bxml\.dom\.minidom\.(parse|parseString)\s*\("],
        fix="Use defusedxml.minidom instead of xml.dom.minidom.",
        category="xml",
    ),
    Rule(
        rule_id="PY076", name="xml-bad-pulldom",
        severity=Severity.MEDIUM,
        description="xml.dom.pulldom parsing untrusted XML is vulnerable to XML attacks.",
        cwe="CWE-611",
        patterns=[r"\bxml\.dom\.pulldom\.(parse|parseString)\s*\("],
        fix="Use defusedxml.pulldom instead of xml.dom.pulldom.",
        category="xml",
    ),

    # ---- CATEGORY 9: Weak Cryptography (B304-B305) ----
    Rule(
        rule_id="PY080", name="insecure-ciphers",
        severity=Severity.HIGH,
        description="Use of insecure ciphers (ARC2, ARC4, Blowfish, DES, XOR, IDEA, CAST5, SEED, TripleDES).",
        cwe="CWE-327",
        patterns=[
            r"\bCrypto\.Cipher\.(ARC2|ARC4|Blowfish|DES|XOR)\.new\s*\(",
            r"\bCryptodome\.Cipher\.(ARC2|ARC4|Blowfish|DES|XOR)\.new\s*\(",
            r"\bcryptography\.hazmat\.primitives\.ciphers\.algorithms\.(ARC4|Blowfish|IDEA|CAST5|SEED|TripleDES)\s*\(",
        ],
        fix="Use AES (128/256-bit) from cryptography.hazmat.primitives.ciphers.algorithms.AES.",
        category="crypto",
    ),
    Rule(
        rule_id="PY081", name="ecb-cipher-mode",
        severity=Severity.MEDIUM,
        description="ECB cipher mode reveals data patterns and is not semantically secure.",
        cwe="CWE-327",
        patterns=[r"\bcryptography\.hazmat\.primitives\.ciphers\.modes\.ECB\s*\("],
        fix="Use CBC, GCM, or CTR mode instead of ECB.",
        category="crypto",
    ),

    # ---- CATEGORY 10: Insecure Protocols (B312, B321) ----
    Rule(
        rule_id="PY082", name="insecure-protocols",
        severity=Severity.HIGH,
        description="Use of insecure plaintext protocols (Telnet, FTP). Use SSH/SCP/SFTP instead.",
        cwe="CWE-319",
        patterns=[
            r"\btelnetlib\.",  # telnetlib.*
            r"\bftplib\.",     # ftplib.*
            r"\bfrom\s+telnetlib\s+import",
            r"\bfrom\s+ftplib\s+import",
            r"\bimport\s+telnetlib",
            r"\bimport\s+ftplib",
        ],
        fix="Replace Telnet with SSH (paramiko/fabric). Replace FTP with SFTP/SCP.",
        category="network",
    ),
    # ═══ v0.5: SQL + Secrets ═══
    Rule(rule_id="PY083", name="sql-injection", severity=Severity.CRITICAL, description="SQL query with string concatenation.", cwe="CWE-89", patterns=[r"execute\s*\(.*SELECT.*\+", r"execute\s*\(.*INSERT.*\+"], fix="Use parameterized queries.", category="injection"),
    Rule(rule_id="PY084", name="hardcoded-password", severity=Severity.CRITICAL, description="Hardcoded password.", cwe="CWE-798", patterns=[r"DB_PASSWORD\s*=\s*\S+", r"PASSWD\s*=\s*\S{4,}"], fix="Use env vars.", category="secrets"),
    # ═══ v0.7: 30 new rules ═══
    Rule(rule_id="PY090", name="jsonpickle-dangerous", severity=Severity.CRITICAL, description="jsonpickle.decode() code execution.", cwe="CWE-502", patterns=[r"jsonpickle\.decode\s*\("], fix="Use json.loads().", category="injection"),
    Rule(rule_id="PY091", name="shelve-open", severity=Severity.HIGH, description="shelve.open() on untrusted data.", cwe="CWE-502", patterns=[r"shelve\.open\s*\("], fix="Use json.", category="injection"),
    Rule(rule_id="PY093", name="ctypes-cdll", severity=Severity.HIGH, description="ctypes.CDLL untrusted libs.", cwe="CWE-502", patterns=[r"ctypes\.CDLL\s*\("], fix="Load trusted only.", category="injection"),
    Rule(rule_id="PY095", name="shutil-rmtree-unvalidated", severity=Severity.CRITICAL, description="shutil.rmtree unvalidated.", cwe="CWE-73", patterns=[r"shutil\.rmtree\s*\(.*\+"], fix="Validate paths.", category="path"),
    Rule(rule_id="PY096", name="redirect-unvalidated", severity=Severity.HIGH, description="Open redirect.", cwe="CWE-601", patterns=[r"redirect\s*\(.*request"], fix="Validate URLs.", category="network"),
    Rule(rule_id="PY097", name="cors-wildcard", severity=Severity.MEDIUM, description="CORS wildcard.", cwe="CWE-942", patterns=[r"Access-Control-Allow-Origin.*\*"], fix="Restrict CORS.", category="network"),
    Rule(rule_id="PY098", name="jwt-no-verify", severity=Severity.CRITICAL, description="JWT no verify.", cwe="CWE-345", patterns=[r"jwt\.decode.*verify.*False"], fix="Always verify.", category="crypto"),
    Rule(rule_id="PY099", name="jwt-hardcoded-secret", severity=Severity.CRITICAL, description="JWT hardcoded secret.", cwe="CWE-798", patterns=[r"jwt\.encode.*secret", r"JWT_SECRET\s*=\s*\S+"], fix="Load from env.", category="secrets"),
    Rule(rule_id="PY100", name="subprocess-shell-true", severity=Severity.CRITICAL, description="subprocess shell=True.", cwe="CWE-78", patterns=[r"subprocess\..*shell\s*=\s*True"], fix="Use shell=False.", category="injection"),
    Rule(rule_id="PY101", name="input-eval-chain", severity=Severity.HIGH, description="input() to eval.", cwe="CWE-95", patterns=[r"eval\s*\(.*input"], fix="Never eval input.", category="injection"),
    Rule(rule_id="PY102", name="lxml-unsafe-parse", severity=Severity.HIGH, description="lxml XXE.", cwe="CWE-611", patterns=[r"lxml\.etree\.parse\s*\("], fix="Use safe parser.", category="xml"),
    Rule(rule_id="PY104", name="private-key-hardcoded", severity=Severity.CRITICAL, description="Private key in code.", cwe="CWE-798", patterns=[r"BEGIN.*PRIVATE.*KEY"], fix="Never embed keys.", category="secrets"),
    Rule(rule_id="PY105", name="ecb-mode", severity=Severity.MEDIUM, description="ECB mode.", cwe="CWE-327", patterns=[r"MODE_ECB"], fix="Use CBC/GCM.", category="crypto"),
    Rule(rule_id="PY107", name="django-debug-true", severity=Severity.HIGH, description="DEBUG=True.", cwe="CWE-489", patterns=[r"DEBUG\s*=\s*True"], fix="Set DEBUG=False.", category="config"),
    Rule(rule_id="PY108", name="django-secret-weak", severity=Severity.HIGH, description="Django SECRET_KEY hardcoded.", cwe="CWE-798", patterns=[r"SECRET_KEY\s*=\s*\S{8,}"], fix="Load from env.", category="secrets"),
    Rule(rule_id="PY109", name="flask-debug-true", severity=Severity.HIGH, description="Flask debug=True.", cwe="CWE-489", patterns=[r"app\.run.*debug\s*=\s*True"], fix="Never debug=True.", category="config"),
    Rule(rule_id="PY110", name="sql-fstring", severity=Severity.CRITICAL, description="SQL f-string.", cwe="CWE-89", patterns=[r"execute\s*\(\s*f.*SELECT"], fix="Use parameterized.", category="injection"),
    Rule(rule_id="PY112", name="tarfile-extractall", severity=Severity.HIGH, description="tarfile path traversal.", cwe="CWE-22", patterns=[r"tarfile.*extractall"], fix="Validate paths.", category="path"),
    Rule(rule_id="PY113", name="zipfile-extractall", severity=Severity.HIGH, description="zipfile path traversal.", cwe="CWE-22", patterns=[r"zipfile.*extractall"], fix="Validate paths.", category="path"),
    Rule(rule_id="PY114", name="logging-sensitive", severity=Severity.MEDIUM, description="Logging secrets.", cwe="CWE-532", patterns=[r"log.*password", r"logger.*password"], fix="Never log secrets.", category="secrets"),
    Rule(rule_id="PY116", name="random-seed-fixed", severity=Severity.MEDIUM, description="Fixed random seed.", cwe="CWE-330", patterns=[r"random\.seed\s*\(\s*\d"], fix="Use secrets.", category="crypto"),
    Rule(rule_id="PY118", name="flask-send-file", severity=Severity.HIGH, description="Flask send_file traversal.", cwe="CWE-22", patterns=[r"send_file\s*\(.*request"], fix="Validate paths.", category="path"),
    Rule(rule_id="PY119", name="django-raw-sql", severity=Severity.CRITICAL, description="Django raw() injection.", cwe="CWE-89", patterns=[r"\.raw\s*\(.*\+"], fix="Use parameterized.", category="injection"),
    Rule(rule_id="PY120", name="unverified-ssl", severity=Severity.HIGH, description="SSL CERT_NONE.", cwe="CWE-295", patterns=[r"CERT_NONE"], fix="Never disable SSL.", category="network"),
    Rule(rule_id="PY121", name="os-system-user-input", severity=Severity.CRITICAL, description="os.system with input.", cwe="CWE-78", patterns=[r"os\.system\s*\(.*input"], fix="Use subprocess.", category="injection"),
    Rule(rule_id="PY123", name="yaml-load-all", severity=Severity.HIGH, description="yaml.load_all unsafe.", cwe="CWE-502", patterns=[r"yaml\.load_all\s*\("], fix="Use safe_load_all.", category="injection"),
    Rule(rule_id="PY124", name="sql-format-method", severity=Severity.CRITICAL, description="SQL .format() injection.", cwe="CWE-89", patterns=[r"execute\s*\(.*\.format.*SELECT"], fix="Use parameterized.", category="injection"),
    Rule(rule_id="PY125", name="paramiko-autoadd", severity=Severity.MEDIUM, description="Paramiko AutoAddPolicy.", cwe="CWE-295", patterns=[r"AutoAddPolicy"], fix="Use RejectPolicy.", category="network"),
    Rule(rule_id="PY126", name="flask-secret-weak", severity=Severity.HIGH, description="Flask secret_key weak.", cwe="CWE-798", patterns=[r"secret_key\s*=\s*\S{4,}"], fix="Load from env.", category="secrets"),
]


# ============================================================
# Free tier: first 25 rules; Pro tier: all 50+
# ============================================================
FREE_RULE_COUNT = 30


def get_rules(tier: str = "free") -> List[Rule]:
    """Return rules based on tier level."""
    if tier == "pro":
        return PYTHON_RULES
    return PYTHON_RULES[:FREE_RULE_COUNT]


def get_rules_by_category(category: str) -> List[Rule]:
    """Filter rules by category."""
    return [r for r in PYTHON_RULES if r.category == category]


def get_critical_rules() -> List[Rule]:
    """Return only CRITICAL severity rules."""
    return [r for r in PYTHON_RULES if r.severity == Severity.CRITICAL]
