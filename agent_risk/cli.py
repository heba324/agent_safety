import argparse
import json
from pathlib import Path
from typing import Sequence

from agent_risk.cascade import CascadeDetector
from agent_risk.config import load_env_file
from agent_risk.detector import BehaviorChainDetector
from agent_risk.judge import OpenAICompatibleJudge


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-risk",
        description="Detect risks in a JSONL coding-agent behavior chain.",
    )
    parser.add_argument("path", help="Path to a JSONL behavior-chain file.")
    parser.add_argument(
        "--judge",
        choices=("rules-only", "openai-compatible"),
        default="rules-only",
        help="Optional LLM judge backend for review cases.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = Path(args.path).read_text(encoding="utf-8")
    detector = _build_detector(args.judge)
    report = detector.detect_jsonl(payload)
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    return _exit_code_for_action(report.recommended_action)


def _build_detector(judge_mode: str):
    if judge_mode == "openai-compatible":
        load_env_file()
        return CascadeDetector(judge=OpenAICompatibleJudge.from_env())
    return BehaviorChainDetector()


def _exit_code_for_action(action: str) -> int:
    if action == "allow":
        return 0
    if action == "require_review":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
