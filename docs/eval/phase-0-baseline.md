# DS 评测报告 — Phase 0: 基线评估

> 2026-06-19 | 评测人：DeepSeek v4-flash | 监督：军师

---

## 测试环境
- 模型：deepseek-v4-flash @ 127.0.0.1:57321
- 参数：temperature=0, max_tokens=256
- 测试集：AgentGuard 源码自身（17 文件，~4000 行 Python）

---

## Phase 0 基线

### 规则覆盖率

对 AgentGuard 自身项目扫描：

```
agentguard scan . --format json
```

| 指标 | 值 |
|---|---|
| 总发现 | 待运行 |
| CRITICAL | 待运行 |
| HIGH | 待运行 |
| MEDIUM | 待运行 |
| LOW | 待运行 |

### 规则覆盖矩阵

| 类别 | 规则数 | 是否命中真实项目 | 备注 |
|---|---|---|---|
| injection | 7 | 待验证 | eval/exec/pickle等 |
| path_traversal | 3 | 待验证 | |
| secrets | 3 | 待验证 | |
| crypto | 5 | 待验证 | |
| network | 3 | 待验证 | |
| xml | 7 | 待验证 | 新规则 |
| agent | 3 | 待验证 | |
| general | 2 | 待验证 | |

---

## 状态：⏳ 待运行

> 评测流程：`agentguard scan agentguard/ --format json` → 检查输出 → 填入上表 → 判定通过/不通过
