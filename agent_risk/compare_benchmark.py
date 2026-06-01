import argparse
import json
from pathlib import Path
from typing import Sequence

from agent_risk.benchmark import evaluate_records, load_records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-risk-compare-benchmark",
        description="Compare detector modes on one benchmark manifest.",
    )
    parser.add_argument("manifest")
    parser.add_argument(
        "--modes",
        default="rules-only,openai-compatible",
        help="Comma-separated modes: rules-only,openai-compatible.",
    )
    parser.add_argument("--output", help="Optional path to write the JSON report.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest_path = Path(args.manifest)
    records = load_records(manifest_path)
    results = {}

    for mode in _parse_modes(args.modes):
        if mode == "rules-only":
            results[mode] = _compact(evaluate_records(records))
        elif mode == "openai-compatible":
            results[mode] = _compact(
                evaluate_records(records, judge=_openai_compatible_judge())
            )
        else:
            raise SystemExit(f"Unsupported mode: {mode}")

    payload = {"manifest": str(manifest_path), "results": results}
    output_text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output_text + "\n", encoding="utf-8")
    print(output_text)
    return 0


def _parse_modes(raw: str) -> list:
    return [mode.strip() for mode in raw.split(",") if mode.strip()]


def _compact(report: dict) -> dict:
    return {
        "detector_mode": report["detector_mode"],
        "total": report["total"],
        "action_accuracy": report["action_accuracy"],
        "unsafe_precision": report["unsafe_precision"],
        "unsafe_recall": report["unsafe_recall"],
        "unsafe_f1": report["unsafe_f1"],
        "false_positive_count": report["false_positive_count"],
        "false_negative_count": report["false_negative_count"],
        "family_metrics": report["family_metrics"],
    }


def _openai_compatible_judge():
    from agent_risk.config import load_env_file
    from agent_risk.judge import OpenAICompatibleJudge

    load_env_file()
    return OpenAICompatibleJudge.from_env()


if __name__ == "__main__":
    raise SystemExit(main())
