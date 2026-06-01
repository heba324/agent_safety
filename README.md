# OpenClaw Agent Risk Research Prototype

This repository is a research prototype for modeling and detecting data-security
risks in coding agents. The first milestone is deliberately small: represent an
agent behavior chain, apply deterministic risk rules, and compute a chain-level
risk assessment.

## Current Scope

- Normalize agent events such as file reads, shell commands, network requests,
  model messages, and tool calls.
- Detect obvious high-risk behavior with deterministic rules.
- Score behavior chains that combine sensitive-file access with external
  network destinations.
- Keep sample JSONL behavior chains for repeatable experiments.

## Event Format

Each line in a sample file is one JSON event:

```json
{"step": 1, "event_type": "file_read", "target": ".env", "content_summary": "read environment variables"}
```

Core fields:

- `step`: integer position in the behavior chain.
- `event_type`: one of `model_message`, `tool_call`, `file_read`, `file_write`,
  `shell_command`, or `network_request`.
- `target`: file path, command, URL, or tool name.
- `content_summary`: short natural-language summary of what happened.
- `metadata`: optional structured context.

## First Research Hypothesis

Behavior-chain detection should outperform single-step checking for coding-agent
data-security risks because many attacks only become clear when sensitive access
and later external movement are linked.

## Run Tests

```powershell
conda activate agent_safety
python -m pytest -q
```

If the environment does not exist yet and online conda metadata access works:

```powershell
conda env create -f environment.yml
```

On this machine the initial environment was created from local cache with:

```powershell
conda create -y -n agent_safety python=3.10 pytest
```

## Run A Detection Report

```powershell
conda activate agent_safety
python -m agent_risk.cli data/samples/sensitive_exfiltration.jsonl
```

Exit codes:

- `0`: allowed behavior chain.
- `1`: risk found and human review is recommended.
- `2`: high-risk behavior chain should be blocked.

To enable the OpenAI-compatible LLM judge for review cases:

```powershell
$env:AGENT_RISK_LLM_PROVIDER="openai_compatible"
$env:AGENT_RISK_LLM_MODEL="Qwen/Qwen3-8B"
$env:AGENT_RISK_LLM_BASE_URL="https://api.siliconflow.cn/v1"
$env:AGENT_RISK_LLM_API_KEY="your_api_key"

python -m agent_risk.llm_check
python -m agent_risk.cli data/samples/supply_chain_manifest_write.jsonl --judge openai-compatible
```

You can also put the same values in a local `.env` file in the project root.
Do not commit real API keys.

## Run Benchmark v0

```powershell
conda activate agent_safety
python -m agent_risk.benchmark data/benchmark_v0.jsonl
```

The benchmark manifest stores one expected action per sample behavior chain. The
current metrics report action accuracy plus unsafe precision, recall, F1, false
positives, false negatives, and per-family metrics.

## Generate Benchmark Samples

```powershell
conda activate agent_safety
python -m agent_risk.generator --output-dir data/generated_samples --manifest data/benchmark_generated.jsonl --variants-per-family 3
python -m agent_risk.benchmark data/benchmark_generated.jsonl
```

Generated samples follow the Chinese annotation guideline in
`docs/研究笔记/行为链标注规范_v0.md`.

## Next Milestones

1. Add benign hard negatives, such as legitimate `.env.example` reads and internal API tests.
2. Add prompt-injection-to-exfiltration task families.
3. Add a lightweight LLM-based judge behind the same detector interface.
