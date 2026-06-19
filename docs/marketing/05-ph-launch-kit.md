# AgentGuard Pro — ProductHunt 发布物料包 v1.0

> 军师出品。6/23 周二发布。

---

## 一、Tagline

```
AgentGuard Pro — Finds what rules can't see.
Python SAST + LLM heuristic discovery + one-click auto-fix.
```

---

## 二、PH 帖子正文

```
I got tired of SAST tools that flood you with false positives and leave you to fix everything by hand.

So I built AgentGuard Pro:

🧠 34 built-in rules + Bandit's 100+ engine — known vulns: covered
🔍 Local DeepSeek LLM second-pass review — false positives: near zero
🪄 Pipeline: scan → review → fix — one command
🌙 [Labs] LLM heuristic discovery — finds what no rule can describe

It's Python-only. It runs locally. It's open source (AGPLv3).

Free tier: full 34 rules + Bandit base.
Pro ($29/mo): DS review + pipeline auto-fix + LLM heuristic discovery.

pip install agentguard2027
https://github.com/difcn2026/agentguard

🚀 PH launch special: $149/year (first 100, code PH2025)

Built by a solo hacker who believes security tools should be sharp, not bloated. Feedback welcome — roast me.
```

---

## 三、首条评论（自己发，引导讨论）

```
Why Python-only?

Python is where I have the deepest expertise, and where SAST tools have the worst false positive rates (dynamic typing = harder static analysis).

The LLM heuristic pass is the real innovation here — it reads code logic, not just pattern-matches. Other tools can't do that.

If this takes off, I'll add JS/TS next. What language would you want after Python?
```

---

## 四、Maker's Reply 模板

**Q: How is this different from Bandit?**
> Bandit is the scanner engine we use under the hood. We add: ML false-positive filtering, LLM second-pass review, one-click auto-fix, and [Labs] heuristic discovery. Bandit finds problems. AgentGuard fixes them.

**Q: Does the LLM send my code to OpenAI?**
> No. We use local DeepSeek API (127.0.0.1:57321). Your code never leaves your machine. The Pro tier uses the same local setup.

**Q: Why not just use Semgrep?**
> Semgrep is great for multi-language. AgentGuard is laser-focused on Python — which means deeper rules, fewer FPs, and an auto-fixer that actually works. Different tools, different philosophy.

**Q: Pricing seems low. Sustainable?**
> Solo developer, low overhead. If it grows, pricing grows with value. Early adopters get locked in at $149/yr.

---

## 五、社交媒体帖子

### Twitter/X

```
Built a Python SAST that does what no other tool can:

It reads your code with an LLM and finds security bugs that have NO rule to catch them.

Race conditions. Swallowed exceptions. TOCTOU.

pip install agentguard2027
```

### Reddit (r/Python, r/netsec)

```
Title: I built a Python SAST that uses LLM to find vulnerabilities no rule can catch

Body: [简要说明 + 技术细节 + GitHub 链接]

Rules:
- r/Python: focus on dev workflow, pip install, CLI
- r/netsec: focus on false positive rates, LLM approach, comparison with Bandit/Semgrep
```

### V2EX

```
标题：写了一个能发现[规则查不到]的漏洞的 Python 安全扫描器

内容：极客向，强调独立开发、开源、本地运行、命令行美学
```

### Hacker News (Show HN)

```
Show HN: AgentGuard Pro — Python SAST with LLM heuristic vulnerability discovery

[复制 PH 帖子正文，加技术细节]
```

---

## 六、发布日时间线

| 时间 (UTC+8) | 动作 |
|---|---|
| 06:00 | PH 帖子定时发布 |
| 06:05 | 自己发首评 |
| 06:30 | Reddit r/Python 发帖 |
| 07:00 | V2EX 发帖 |
| 08:00 | Twitter 发帖 |
| 10:00 | Hacker News Show HN |
| 全天 | 回复每一条评论 |
| 22:00 | 发感谢帖，公布首日数据 |

---

## 七、发布前检查清单

- [ ] GitHub repo README 更新（含 GIF demo）
- [ ] PyPI v0.3.0 发布
- [ ] 落地页部署（GitHub Pages）
- [ ] License server 确认在线（47.236.24.76:8989）
- [ ] Demo 服务器确认在线（47.236.24.76:1088）
- [ ] 桌面 exe 下载链接就位
- [ ] PH 帖子 + 图片/GIF 准备
- [ ] Maker profile 完善
- [ ] 优惠码 PH2025 配置
