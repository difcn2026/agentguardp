# AgentGuard Pro — 落地页文案 v1.0

> 中英文双版。结构：Hero → 核心卖点×3 → 黑科技 → 对比表 → CTA

---

## 🇨🇳 中文版

### Hero

```
AgentGuard Pro

能发现「规则查不到」的漏洞。

Python 代码安全扫描 → 自动修复。本地运行。极客打造。
```

### CTA 按钮

```
[ 立即安装  pip install agentguard2027 ]
[ 查看 Demo → ]
```

---

### 三个卖点

**扫得全。34 条内置规则 + Bandit 100+底座。**
eval、pickle、subprocess、yaml、XML、弱加密、密钥泄露——一个不漏。Python 安全，只做 Python。

**审得准。DeepSeek 本地 LLM 二次把关。**
SAST 工具通病：40-60% 误报。我们拿 DS 再筛一遍，压到接近零。数据不出你机器。

**修得快。一条命令，从扫描到修复。**
`agentguard pipeline ./src --bandit --ds` → scan → review → fix → 干干净净。

---

### 黑科技区

```
[Labs] LLM Heuristic Discovery

不是规则匹配。是大模型逐行读你的代码，找出——

  竞态条件     异常吞没     时序依赖     权限检查缺失

没有规则能描述的危险，规则当然查不到。但它能。

同类产品用后视镜开车，AgentGuard 带着夜视仪。
```

---

### 对比表

| | Bandit | Semgrep | AgentGuard Pro |
|---|---|---|---|
| Python 规则 | 100+ | 多语言 | 34 + Bandit 100+ |
| 误报过滤 | ❌ | ❌ | LLM 二审 |
| 自动修复 | ❌ | ❌ | ✅ pipeline |
| LLM 启发发现 | ❌ | ❌ | ✅ [Labs] |
| 本地运行 | ✅ | ✅ | ✅ |
| 定价 | 免费 | 免费/$40 | 免费版 + Pro $29 |

---

### 底部

```
开源 · 本地运行 · 不做数据收集

pip install agentguard2027

GitHub: difcn2026/agentguard
```

---

## 🇬🇧 English Version

### Hero

```
AgentGuard Pro

Finds what rules can't see.

Python code security scanner → auto-fixer. Local-first. Built by hackers.
```

### CTA

```
[  pip install agentguard2027  ]
[  View Demo →  ]
```

---

### Three Pillars

**Comprehensive. 34 built-in rules + Bandit's 100+ engine.**
eval, pickle, subprocess, yaml, XML, weak crypto, secret leaks — covered. Python only, Python deep.

**Precise. Local LLM second-pass review.**
Every SAST tool has 40-60% false positives. We run DeepSeek locally to cut it to near zero. Your data stays on your machine.

**Fast fix. One command, scan to repair.**
`agentguard pipeline ./src --bandit --ds` → scan → review → fix → done.

---

### Black Tech

```
[Labs] LLM Heuristic Discovery

Not pattern matching. An LLM reads your code line by line, finding—

  Race conditions     Swallowed exceptions     Timing bugs     Missing auth checks

Things no regex pattern can describe. So no rule catches them. But it does.

Other tools drive with rearview mirrors. AgentGuard has night vision.
```

---

### Comparison

| | Bandit | Semgrep | AgentGuard Pro |
|---|---|---|---|
| Python rules | 100+ | Multi-lang | 34 + Bandit 100+ |
| FP filtering | No | No | LLM review |
| Auto-fix | No | No | Yes (pipeline) |
| Heuristic discovery | No | No | Yes [Labs] |
| Local-only | Yes | Yes | Yes |
| Pricing | Free | Free/$40 | Free + Pro $29 |

---

### Footer

```
Open source · Local-first · Zero telemetry

pip install agentguard2027

GitHub: difcn2026/agentguard
```
