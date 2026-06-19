# AgentGuard Pro — LLM 无规则发现 技术规格 v1.0

> 军师出品。此文档即工程规格书——小黑按此实现。

---

## 一、产品承诺（对外）

> AgentGuard Pro 能发现「规则查不到」的漏洞。

具体三样：
1. 竞态条件（race condition）
2. 异常吞没（swallowed exception）
3. 时序/时间戳依赖（timing bugs）
4. 权限检查缺失（missing auth/guard）
5. 逻辑不一致（logic contradictions）

---

## 二、实现方案

### 2.1 管线位置

```
scan (34 rules + Bandit)
  ↓
ML filter (ml_filter.py)
  ↓
DS review (llm_review.py) — 分类 TP/FP
  ↓
**LLM heuristic pass** ← 本规格
  ↓
fix (code_fixer.py)
```

### 2.2 模块：`scanner/llm_heuristic.py`

```python
def heuristic_scan(
    file_path: str,
    code: str,
    existing_findings: list,
    api_url: str = DS_API_URL,
    model: str = "deepseek-v4",
) -> list[HeuristicFinding]:
    """
    对已扫描过的文件做 LLM 启发式审查。
    只找现有规则没覆盖的隐患。
    """
```

### 2.3 LLM Prompt 设计

```
SYSTEM:
You are a senior security engineer performing a code review.
You have ALREADY run static analysis rules and found issues.
Now, look beyond the rules — read the code logic line by line.

Find security risks that NO pattern-based rule could detect:
1. Race conditions (shared state without locks)
2. Swallowed exceptions (except: pass, except: continue)
3. Time-of-check-time-of-use (TOCTOU)
4. Missing authorization checks before sensitive operations
5. Logic bugs that could lead to security bypass

For each finding, output JSON:
{
  "findings": [
    {
      "line_start": 42,
      "line_end": 48,
      "risk_type": "race_condition|swallowed_exception|toctou|missing_auth|logic_bug",
      "severity": "HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "description": "brief explanation",
      "suggestion": "how to fix"
    }
  ]
}

IMPORTANT: Only report issues NOT already covered by the existing findings listed below.

USER:
Existing findings (already handled):
{existing_findings_summary}

Code to review:
```python
{code}
```
```

### 2.4 输出格式

```python
@dataclass
class HeuristicFinding:
    file: str
    line_start: int
    line_end: int
    risk_type: str       # race_condition | swallowed_exception | toctou | missing_auth | logic_bug
    severity: str        # HIGH | MEDIUM | LOW
    confidence: float    # 0.0 - 1.0
    description: str
    suggestion: str
    source: str = "llm_heuristic"  # 区别于规则扫描
```

### 2.5 展示规则

在 CLI 和 GUI 中，LLM 启发发现**独立展示**，不混入主结果：

```
─── Rule-based findings (34 rules + Bandit) ───
  [PY001] L12: eval() used
  [PY005] L42: pickle.loads() on untrusted data

─── [Labs] LLM Heuristic Discovery ───
  [race_condition] L42-L48: shared counter without lock in threaded context
  [swallowed_exception] L55: except: pass masks all errors
  [toctou] L71: file existence check then open — race window
```

### 2.6 CLI 集成

```bash
agentguard scan ./src --labs          # 启用 LLM 启发
agentguard pipeline ./src --labs      # 全管线 + LLM 启发
```

默认关闭，`--labs` 显式开启。避免默认开启的用户困惑。

### 2.7 GUI 集成

在桌面端结果区底部增加 `[Labs]` 折叠面板，默认收起。点击展开显示启发式发现。

---

## 三、性能约束

| 参数 | 值 | 说明 |
|---|---|---|
| 每次审查最大行数 | 300 行 | 超过则分块 |
| 单文件超时 | 15s | DS API 超时 |
| 并发 | 串行 | 不并行，避免 API 压力 |
| 缓存 | 同文件同 hash 跳过 | 避免重复审查 |

---

## 四、False Positive 控制

LLM 启发发现的 FP 率天然高于规则扫描。控制策略：

1. **confidence 阈值**：只展示 confidence ≥ 0.6 的结果
2. **独立标记**：`[Labs]` 区明确标注 "experimental"
3. **不参与自动修复**：LLM 发现的问题不进入 `fix` 流程，只建议
4. **用户反馈回路**：未来版本加 👍/👎 标记，用于调优 prompt

---

## 五、与 DS review 的区别

| | DS Review | LLM Heuristic |
|---|---|---|
| 做什么 | 判断规则结果 TP/FP | 从零发现新问题 |
| 输入 | 单条 finding | 整段代码 + 已有 findings |
| 输出 | TP/FP/UNKNOWN | HeuristicFinding[] |
| 调用时机 | 每个 finding 一次 | 每个文件一次 |
| 是否参与 fix | 是（过滤误报） | 否（只建议） |
| 标记 | 无特殊标记 | [Labs] |

---

## 六、实现计划

| 序号 | 任务 | 文件 |
|---|---|---|
| 1 | 新增 `scanner/llm_heuristic.py` | 新文件 |
| 2 | `_handle_scan` 增加 `use_labs` 参数 | desktop.py |
| 3 | CLI 增加 `--labs` flag | cli.py |
| 4 | Pipeline 增加 phase 2.5 | pipeline.py |
| 5 | GUI 结果区增加 [Labs] 面板 | gui.py / desktop.py |
