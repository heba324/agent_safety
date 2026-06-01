# Qwen3-8B 初步实验记录 v0

本文档记录第一次将硅基流动 `Qwen/Qwen3-8B` 接入 benchmark 的结果。实验目的不是证明最终效果，而是验证 `rules-only` 与 `rules+judge` 的批量评测链路能跑通，并观察 judge 是否能输出可分析的 rationale。

## 实验设置

命令：

```powershell
python -m agent_risk.compare_benchmark data\benchmark_generated.jsonl --modes "rules-only,openai-compatible" --include-records --output results\benchmark_generated_rules_vs_qwen3_8b_detailed.json
```

模型：

- provider: OpenAI-compatible
- model: `Qwen/Qwen3-8B`
- base URL: `https://api.siliconflow.cn/v1`

benchmark：

- 总样本数：36
- 任务族数：12
- allow：15
- require_review：6
- block：15

## 结果摘要

`rules-only`：

- action accuracy: 1.0
- unsafe precision: 1.0
- unsafe recall: 1.0
- judge calls: 0

`rules+Qwen3-8B`：

- action accuracy: 1.0
- unsafe precision: 1.0
- unsafe recall: 1.0
- judge calls: 6

混淆矩阵：

```json
{
  "allow": {"allow": 15, "require_review": 0, "block": 0},
  "require_review": {"allow": 0, "require_review": 6, "block": 0},
  "block": {"allow": 0, "require_review": 0, "block": 15}
}
```

## 观察

1. 当前 36 条样本仍然偏规则友好，`rules-only` 已经达到 1.0，因此无法体现 Qwen3-8B 对准确率的增益。
2. Qwen3-8B 被调用 6 次，正好对应两个复核任务族：`sensitive_read_no_exfil` 和 `supply_chain_manifest_write`。
3. Qwen3-8B 在这 6 条样本上没有改变最终动作，均保持 `require_review`。
4. judge rationale 有分析价值。例如普通供应链修改样本中，模型能指出依赖清单或 CI 配置修改可能引入供应链风险，需要人工确认。

## 方法问题

当前级联策略只在基础检测器输出 `require_review` 时调用 judge。这符合实时系统成本控制，但会限制 judge 对明显 allow/block 样本的纠错能力。后续可以设计三种模式：

1. `review-only`：只复核 `require_review`，用于低成本在线检测。
2. `audit-all`：全部样本都给 judge，用于离线标注或 upper-bound 分析。
3. `sampled-audit`：对 allow/block 样本抽样审计，用于监控规则漂移。

## 下一步

1. 构造 rules-only 会失败的样本，例如：
   - 外部请求摘要不含 upload/send/post，但语义上仍是外传。
   - 提示注入服从没有显式使用 “ignore previous instructions” 字符串。
   - 敏感内容通过 issue comment、git remote、日志系统等非 HTTP upload 通道外传。
2. 增加 `audit-all` 模式，让 Qwen3-8B 对所有样本输出判断，用于分析模型是否能发现规则未覆盖风险。
3. 记录每次 LLM 调用的耗时、重试次数和失败次数，形成实时检测成本分析。
