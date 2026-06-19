# AgentGuard Pro — 定价策略 v1.0

> 军师出品。6/23 ProductHunt 发布即生效。

---

## 分层

### Free（永远免费）

| 内容 | 说明 |
|---|---|
| 34 条内置规则 | 全量，不限 |
| Bandit 底座 | 100+ 规则，扫描用 |
| 基本报告 | terminal / JSON / SARIF / markdown |
| CLI + GUI | 全功能 |
| 开源 | AGPLv3 |

**不给的**：DS 审核、Pipeline 修复、LLM 启发发现

### Pro — $29/月 或 $199/年

| 内容 | 说明 |
|---|---|
| Free 全部 | + |
| DS 审核 | 本地 LLM 二审，误报压到近零 |
| Pipeline 一键修复 | scan → review → fix 一条命令 |
| **[Labs] LLM 启发发现** | **黑科技核心** |
| 数据飞轮订阅 | 每月更新的 ML 模型 |
| 优先支持 | GitHub Issues 优先响应 |

### Team — $99/月

| 内容 |
|---|
| Pro 全部 |
| CI/CD 集成（GitHub Actions 模板） |
| 团队管理面板 |
| SSO（未来） |

---

## 定价逻辑

**为什么不是 $49/$99？**

- 目标用户是独立开发者和小团队，不是企业采购部门
- $29 对标：Cursor Pro $20, Copilot $10, Semgrep Team $40/contributor
- 位置：比 Copilot 贵（功能专精），比 Semgrep 便宜（我们不是平台）
- 年付 8.3 折 = $199/年 → 用户心理锚点 "不到 200 块"

**免费版给太多怎么办？**

- 34 条全给是故意的——免费版自己扫能发现问题，但修不了、误报多
- 用户花 30 分钟手修误报 → 想起 Pro 一键修 → 转化
- 这叫「痛感转化」，不是「功能阉割」

---

## ProductHunt 专属优惠

```
PH 首发价：$149/年（原 $199，前 100 名）

优惠码：PH2025
有效期：6/23 - 6/30
```

---

## 收款通道

| 通道 | 状态 |
|---|---|
| LemonSqueezy | 待注册（SS 代理后处理） |
| 支付宝/微信 | 未来 |
| Stripe | 需海外主体 |

当前：GitHub Sponsors 过渡 + 手动激活 License。

---

## 一句话总结

> "34 rules scan what you know. [Labs] finds what you don't. $29/mo to never fix a false positive again."
