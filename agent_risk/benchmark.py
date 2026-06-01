import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence

from agent_risk.cascade import CascadeDetector
from agent_risk.detector import BehaviorChainDetector
from agent_risk.judge import LLMJudge, OpenAICompatibleJudge


@dataclass(frozen=True)
class BenchmarkRecord:
    sample_path: Path
    expected_action: str
    expected_risk_types: List[str] = field(default_factory=list)
    sample_id: str = ""
    task_family: str = "unknown"
    evidence_steps: List[int] = field(default_factory=list)
    attack_source: str = "unknown"
    trust_boundary: str = "unknown"
    data_asset: str = "unknown"

    @classmethod
    def from_dict(cls, payload: dict, root: Path) -> "BenchmarkRecord":
        sample_path = Path(payload["sample_path"])
        if not sample_path.is_absolute():
            sample_path = root / sample_path
        return cls(
            sample_path=sample_path,
            expected_action=payload["expected_action"],
            expected_risk_types=list(payload.get("expected_risk_types", [])),
            sample_id=payload.get("sample_id", sample_path.stem),
            task_family=payload.get("task_family", "unknown"),
            evidence_steps=list(payload.get("evidence_steps", [])),
            attack_source=payload.get("attack_source", "unknown"),
            trust_boundary=payload.get("trust_boundary", "unknown"),
            data_asset=payload.get("data_asset", "unknown"),
        )


def load_records(manifest_path: Path) -> List[BenchmarkRecord]:
    root = manifest_path.resolve().parent.parent
    records = []
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(BenchmarkRecord.from_dict(json.loads(line), root=root))
    return records


def evaluate_records(records: Iterable[BenchmarkRecord], judge: LLMJudge | None = None) -> dict:
    detector = CascadeDetector(judge=judge) if judge is not None else BehaviorChainDetector()
    rows = []

    for record in records:
        payload = record.sample_path.read_text(encoding="utf-8")
        report = detector.detect_jsonl(payload)
        predicted_risk_types = sorted(
            set(report.overall.risk_types)
            | {finding.rule_id for finding in report.findings}
        )
        rows.append(
            {
                "sample_id": record.sample_id or record.sample_path.stem,
                "sample_path": str(record.sample_path),
                "task_family": record.task_family,
                "expected_action": record.expected_action,
                "predicted_action": report.recommended_action,
                "expected_risk_types": record.expected_risk_types,
                "predicted_risk_types": predicted_risk_types,
                "judge_recommended_action": (
                    report.judge_decision.recommended_action
                    if report.judge_decision is not None
                    else None
                ),
                "judge_rationale": (
                    report.judge_decision.rationale
                    if report.judge_decision is not None
                    else None
                ),
                "evidence_steps": record.evidence_steps,
                "attack_source": record.attack_source,
                "trust_boundary": record.trust_boundary,
                "data_asset": record.data_asset,
            }
        )

    summary = _summarize(rows)
    summary["detector_mode"] = "rules+judge" if judge is not None else "rules-only"
    return summary


def _summarize(rows: List[dict]) -> dict:
    total = len(rows)
    action_correct = sum(
        1 for row in rows if row["expected_action"] == row["predicted_action"]
    )
    true_positive = sum(
        1
        for row in rows
        if row["expected_action"] != "allow" and row["predicted_action"] != "allow"
    )
    false_positive = sum(
        1
        for row in rows
        if row["expected_action"] == "allow" and row["predicted_action"] != "allow"
    )
    false_negative = sum(
        1
        for row in rows
        if row["expected_action"] != "allow" and row["predicted_action"] == "allow"
    )

    precision = _safe_divide(true_positive, true_positive + false_positive)
    recall = _safe_divide(true_positive, true_positive + false_negative)
    f1 = _safe_divide(2 * precision * recall, precision + recall)

    return {
        "total": total,
        "action_accuracy": _safe_divide(action_correct, total),
        "unsafe_precision": precision,
        "unsafe_recall": recall,
        "unsafe_f1": f1,
        "false_positive_count": false_positive,
        "false_negative_count": false_negative,
        "judge_invocation_count": sum(
            1 for row in rows if row.get("judge_recommended_action") is not None
        ),
        "action_confusion": _action_confusion(rows),
        "family_metrics": _family_metrics(rows),
        "records": rows,
    }


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def _action_confusion(rows: List[dict]) -> dict:
    actions = ("allow", "require_review", "block")
    matrix = {
        expected: {predicted: 0 for predicted in actions}
        for expected in actions
    }
    for row in rows:
        expected = row["expected_action"]
        predicted = row["predicted_action"]
        if expected not in matrix:
            matrix[expected] = {action: 0 for action in actions}
        if predicted not in matrix[expected]:
            matrix[expected][predicted] = 0
        matrix[expected][predicted] += 1
    return matrix


def _family_metrics(rows: List[dict]) -> dict:
    metrics = {}
    for family in sorted({row["task_family"] for row in rows}):
        family_rows = [row for row in rows if row["task_family"] == family]
        summary = _summarize_without_family(family_rows)
        metrics[family] = summary
    return metrics


def _summarize_without_family(rows: List[dict]) -> dict:
    total = len(rows)
    action_correct = sum(
        1 for row in rows if row["expected_action"] == row["predicted_action"]
    )
    true_positive = sum(
        1
        for row in rows
        if row["expected_action"] != "allow" and row["predicted_action"] != "allow"
    )
    false_positive = sum(
        1
        for row in rows
        if row["expected_action"] == "allow" and row["predicted_action"] != "allow"
    )
    false_negative = sum(
        1
        for row in rows
        if row["expected_action"] != "allow" and row["predicted_action"] == "allow"
    )
    precision = _safe_divide(true_positive, true_positive + false_positive)
    recall = _safe_divide(true_positive, true_positive + false_negative)
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    return {
        "total": total,
        "action_accuracy": _safe_divide(action_correct, total),
        "unsafe_precision": precision,
        "unsafe_recall": recall,
        "unsafe_f1": f1,
        "false_positive_count": false_positive,
        "false_negative_count": false_negative,
        "judge_invocation_count": sum(
            1 for row in rows if row.get("judge_recommended_action") is not None
        ),
        "action_confusion": _action_confusion(rows),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-risk-benchmark",
        description="Evaluate the detector against a JSONL benchmark manifest.",
    )
    parser.add_argument("manifest", help="Path to a benchmark JSONL manifest.")
    parser.add_argument(
        "--judge",
        choices=("rules-only", "openai-compatible"),
        default="rules-only",
        help="Optional LLM judge backend for review cases.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = evaluate_records(
        load_records(Path(args.manifest)),
        judge=_build_judge(args.judge),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["false_negative_count"] == 0 else 1


def _build_judge(judge_mode: str):
    if judge_mode == "openai-compatible":
        from agent_risk.config import load_env_file

        load_env_file()
        return OpenAICompatibleJudge.from_env()
    return None


if __name__ == "__main__":
    raise SystemExit(main())
