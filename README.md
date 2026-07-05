# AgentGuard

**The first productized security tool powered by GLM-5.2.** 

Scan → GLM-5.2 verifies → GLM-5.2 fixes → self-validates. One command.

[![PyPI](https://img.shields.io/pypi/v/agentguardp)](https://pypi.org/project/agentguardp/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
![Powered by GLM-5.2](https://img.shields.io/badge/Powered%20by-GLM--5.2-orange)

---

## Why AgentGuard

SAST tools flood you with false positives and leave you to fix everything by hand. AgentGuard is different:

**Rules find suspects. GLM-5.2 confirms, fixes, and verifies.**

| | Bandit | Semgrep | **AgentGuard** |
|---|---|---|---|
| Python rules | 100+ | Multi-lang | **36 + Bandit 100+** |
| JavaScript/TS | - | Multi-lang | **14 rules** |
| FP filtering | - | - | **GLM-5.2 review** |
| Auto-fix | - | - | **GLM-5.2 AI fix (bring your own API key)** |
| Self-validation | - | - | **Re-scan after fix** |
| Pricing | Free | Free/$40 | **Free + Pro $29/mo** |

### GLM-5.2 Security Benchmark

| Model | F1 Score | Cost per finding |
|---|---|---|
| Claude Code | 32-37% | ~$1.02 |
| **GLM-5.2** | **39%** | **$0.17** |

GLM-5.2 outperforms Claude Code in security vulnerability detection at 1/6 the cost. AgentGuard is the first tool to productize this capability.

---

## Quick Start

```bash
# Install
pip install agentguardp

# Scan a project (Python + JavaScript)
agentguard scan ./my-project

# Full pipeline: scan → GLM-5.2 verify → fix → validate
agentguard pipeline ./src --mode dry-run

# JSON output for CI/CD
agentguard scan ./src --format json -o report.json

# SARIF for GitHub Code Scanning
agentguard scan ./src --format sarif -o report.sarif
```

14-day Pro trial included. Full GLM-5.2 AI fix (bring your own API key) activates automatically.

---

## Live Demo

```
$ agentguard pipeline ./vulnerable.py --mode dry-run

[1/4] Scanning...
      Engine: AgentGuard 36 rules + GLM-5.2
      6 findings (4 critical, 1 high, 1 medium)

[2/4] GLM-5.2 reviewing 6 findings...
      CONFIRMED: 6  REJECTED: 0  ERR: 0

[3/4] Fixing 6 findings (mode=dry-run)...
      Fixed: 4  Manual: 2  Files: 1

--- a/vulnerable.py
+++ b/vulnerable.py
@@ -9,7 +9,7 @@
 def run_user_command(user_input):
-    os.system(user_input)
+    subprocess.run(["echo", user_input], check=True)

@@ -15,7 +15,7 @@
 def get_user(username):
-    query = "SELECT * FROM users WHERE name = '" + username + "'"
+    query = "SELECT * FROM users WHERE name = ?"
  cursor.execute(query, (username,))

@@ -21,7 +21,7 @@
 def load_data(data):
-    return pickle.loads(data)
+    return json.loads(data)

@@ -29,7 +29,7 @@
 def calculate(expression):
-    return eval(expression)
+    return ast.literal_eval(expression)

[4/4] Self-validating 1 fixed files...
      OK: vulnerable.py - no new issues introduced

Fixed: 4  |  Manual: 2  |  Files: 1  |  Mode: dry-run
```

**GLM-5.2 didn't just find the SQL injection — it rewrote the query to parameterized form. Bandit can't do this. Semgrep can't do this.**

---

## How It Works

```
agentguard pipeline ./src
    │
    ├── 1. SCAN — 36 Python rules + 14 JS rules + Bandit 100+ (local, instant)
    │
    ├── 2. VERIFY — GLM-5.2 reviews each finding (cloud, ~2s/finding)
    │              Filters false positives, confirms real threats
    │
    ├── 3. FIX — Regex fixes (instant) + GLM-5.2 AI fix (bring your own API key)es (context-aware)
    │            SQL injection → parameterized queries
    │            Hardcoded passwords → environment variables
    │            eval() → ast.literal_eval()
    │
    └── 4. VALIDATE — Re-scan fixed code, confirm no new issues
```

**Rules find suspects. GLM-5.2 confirms, fixes, and verifies.**

---

## Languages

| Language | Rules | Auto-fix |
|---|---|---|
| **Python** | 36 built-in + Bandit 100+ | Regex + GLM-5.2 cloud |
| **JavaScript/TypeScript** | 14 built-in | Regex + GLM-5.2 cloud |

Supported vulnerabilities: eval/exec, command injection, SQL injection, XSS, 
path traversal, hardcoded secrets, weak crypto (MD5/SHA1), SSRF, SSL bypass, 
prototype pollution, pickle deserialization, prompt injection, and more.

---

## Pricing

| Plan | Price | Features |
|---|---|---|
| **Free** | $0 | 20 rules + regex fix (offline) |
| **Pro Trial** | $0 (14 days) | Full Pro, auto-activated on install |
| **Pro** | $29/mo or $149/yr | All rules + Bandit + GLM-5.2 AI fix (bring your own API key) |

Upgrade at [agentguardp.com](https://agentguardp.com)

---

## GitHub Actions

Add AgentGuard to your CI/CD in 5 lines:

```yaml
- uses: difcn2026/agentguardp@main
  with:
    path: .
    format: sarif
```

SARIF output integrates directly with GitHub Code Scanning.

---

## Install

```bash
pip install agentguardp
```

**Windows Desktop App:** Download from [GitHub Releases](https://github.com/difcn2026/agentguardp/releases)

> SmartScreen warning? Click **More info** → **Run anyway**. Normal for unsigned apps.

---

## Links

- [PyPI](https://pypi.org/project/agentguardp/)
- [GitHub](https://github.com/difcn2026/agentguardp)
- [Website](https://agentguardp.com)
- [License: MIT](LICENSE)

---

## License

MIT — Copyright (c) 2026 XHLS Team

---

> *Rules find suspects. GLM-5.2 confirms, fixes, and verifies.*
