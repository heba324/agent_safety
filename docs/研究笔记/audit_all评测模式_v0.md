# audit-all 评测模式 v0

本文档记录新增的 `audit-all` 评测模式。该模式用于离线研究，不是默认在线部署策略。

## 为什么需要 audit-all

当前在线级联策略是 `review-only`：规则检测器先判断，只有输出 `require_review` 时才调用 LLM judge。这适合低成本在线检测，但有一个研究缺口：LLM 无法审计规则已经判成 `allow` 或 `block` 的样本，因此我们无法观察模型和规则在全样本空间上的分歧。

`audit-all` 的目标是让 LLM judge 对每条行为链都输出判断，从而支持：

1. 发现规则漏报：规则判 `allow`，LLM 判 `require_review` 或 `block`。
2. 发现规则误报：规则判 `block`，LLM 判 `allow` 或 `require_review`。
3. 生成困难样本：优先分析规则和 LLM 分歧最大的样本族。
4. 估计模型上界：离线观察 LLM 在全量样本上的风险推理能力。

## 当前实现

新增检测模式：

- `rules-only`：只使用规则和行为链 scorer。
- `openai-compatible`：默认级联，只复核 `require_review`。
- `audit-all`：所有样本都调用 OpenAI-compatible LLM judge。

逐样本记录中新增：

- `base_predicted_action`：LLM 介入前，规则检测器给出的动作。
- `predicted_action`：当前模式最终动作；在 `audit-all` 中即 judge 动作。
- `base_action_confusion`：规则基线动作到最终动作的混淆矩阵，用于分析规则与 judge 分歧。

命令：

```powershell
python -m agent_risk.compare_benchmark data\benchmark_generated.jsonl --modes "rules-only,audit-all" --include-records --output results\benchmark_generated_audit_all_detailed.json
```

注意：`audit-all` 会对每条样本调用一次 LLM。当前 benchmark 有 48 条样本，因此一次完整评测会产生 48 次 API 调用。

## 与在线系统的关系

`audit-all` 不建议直接作为实时检测路径，因为成本和延迟较高。更合理的系统设计是：

1. 在线路径：`rules-only` 快速放行或阻断明显样本。
2. 在线复核：`review-only` 只把不确定样本交给 LLM。
3. 离线审计：`audit-all` 周期性检查全量样本和真实日志，用于发现规则盲区。

## 下一步实验

1. 在 48 条合成 benchmark 上运行一次 `rules-only,audit-all`，保存 Qwen3-8B 全量判断。
2. 统计规则动作与 judge 动作的分歧矩阵，而不仅是与 expected action 的混淆矩阵。
3. 构造规则明显不足的语义型样本，例如多步数据变换、可信/不可信 remote 区分、诊断日志中的秘密摘要。
4. 将 judge rationale 转化为样本改写方向，形成“规则盲区 -> 新样本族 -> 检测器改进”的闭环。

## 2026-06-03 小规模验证

已在 `data/benchmark_v0.jsonl` 上运行一次 `rules-only,audit-all`，输出文件：

```text
results/benchmark_v0_qwen3_8b_audit_all_detailed.json
```

结果摘要：

- 样本数：6
- `rules-only` action accuracy：1.0
- `audit-all` action accuracy：1.0
- `audit-all` judge 调用次数：6
- 规则动作与 judge 动作：6 条均一致

观察：Qwen3-8B 能够为良性重构、敏感外泄、破坏性命令、提示注入导致删除、供应链清单修改、沙箱逃逸分别给出合理 rationale。当前小基准仍偏简单，后续应重点构造规则与 judge 发生分歧的困难样本。

## 2026-06-03 挑战集验证

已在 `data/challenge_benchmark.jsonl` 上运行 `rules-only,audit-all`，输出文件：

```text
results/challenge_rules_vs_qwen3_8b_audit_all_detailed.json
```

结果显示，Qwen3-8B 的 unsafe F1 从 rules-only 的 0.3333 提升到 0.5714，但 action accuracy 仍为 0.0。它能发现语义外泄需要复核，但对可信 Git push、公开 issue comment 和不可信 issue 驱动的 `git clean -fdx` 仍存在误判。这个结果很适合作为论文中的动机：LLM judge 有语义增益，但也需要更结构化的事件链特征和轻量模型校准。
