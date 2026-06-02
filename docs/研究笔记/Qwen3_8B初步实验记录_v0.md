# Qwen3-8B 初步实验记录 v0

本文档记录将硅基流动 `Qwen/Qwen3-8B` 接入行为链 benchmark 后的阶段性结果。当前目标不是证明最终论文效果，而是确认 `rules-only` 与 `rules+judge` 两种模式可以批量评测、保存明细、输出可分析的风险理由。

## 实验设置

命令：

```powershell
python -m agent_risk.compare_benchmark data\benchmark_generated.jsonl --modes "rules-only,openai-compatible" --include-records --output results\benchmark_generated_rules_vs_qwen3_8b_detailed.json
```

模型配置：

- provider: OpenAI-compatible
- model: `Qwen/Qwen3-8B`
- base URL: `https://api.siliconflow.cn/v1`

Benchmark 配置：

- 总样本数：48
- 任务族数：16
- `allow`：15
- `require_review`：6
- `block`：27

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
  "block": {"allow": 0, "require_review": 0, "block": 27}
}
```

## 观察

1. 当前 48 条合成样本仍然偏规则友好，`rules-only` 已达到 1.0，因此这组结果主要证明评测链路和样本标注一致性，而不能证明 LLM judge 相比规则有明显增益。
2. Qwen3-8B 被调用 6 次，正好对应两个复核型样本族：`sensitive_read_no_exfil` 和 `supply_chain_manifest_write`。
3. Qwen3-8B 在 6 条复核样本上没有改变最终动作，均保持 `require_review`，其 rationale 对后续论文错误分析有价值。
4. 新增的隐蔽外泄样本族包括 HTTP 低语义外传、issue comment 外传、Git remote 外传、混淆提示注入外传。当前这些样本已由基础行为链规则拦截，因此下一步要构造更难的语义型样本，让 LLM judge 或学习模型发挥作用。

## 方法问题

当前级联策略只在基础检测器输出 `require_review` 时调用 judge。这符合在线系统的成本控制目标，但会限制 judge 对明显 `allow` 或 `block` 样本的纠错能力。后续可以设计三种模式：

1. `review-only`：只复核 `require_review`，用于低成本在线检测。
2. `audit-all`：所有样本都交给 judge，用于离线标注、上界分析和规则盲区发现。
3. `sampled-audit`：对 `allow` 与 `block` 样本抽样审计，用于监控规则漂移。

## 下一步

1. 增加 `audit-all` 评测模式，保存所有样本的 Qwen3-8B 判断，用于分析模型与规则的分歧。
2. 构造 rules-only 更容易失败的样本，例如语义正常但上下文异常的工具调用、跨多步的数据变换外泄、以及不含明显关键词的权限升级。
3. 记录每次 LLM 调用的耗时、重试次数、失败次数和 token 规模，为实时检测成本分析做准备。
