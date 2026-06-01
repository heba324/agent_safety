import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence

from agent_risk.detector import BehaviorChainDetector


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


def evaluate_records(records: Iterable[BenchmarkRecord]) -> dict:
    detector = BehaviorChainDetector()
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
                "evidence_steps": record.evidence_steps,
                "attack_source": record.attack_source,
                "trust_boundary": record.trust_boundary,
                "data_asset": record.data_asset,
            }
        )

    return _summarize(rows)


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
        "family_metrics": _family_metrics(rows),
        "records": rows,
    }


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


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
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-risk-benchmark",
        description="Evaluate the detector against a JSONL benchmark manifest.",
    )
    parser.add_argument("manifest", help="Path to a benchmark JSONL manifest.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = evaluate_records(load_records(Path(args.manifest)))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["false_negative_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
