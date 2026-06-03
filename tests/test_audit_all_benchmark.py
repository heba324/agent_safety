from pathlib import Path

from agent_risk.benchmark import BenchmarkRecord, evaluate_records
from agent_risk.judge import JudgeDecision


ROOT = Path(__file__).resolve().parents[1]


class CountingJudge:
    def __init__(self) -> None:
        self.calls = 0

    def review(self, events, base_report):
        self.calls += 1
        return JudgeDecision(
            risk_types=list(base_report.overall.risk_types),
            severity=base_report.overall.severity,
            evidence_steps=list(base_report.overall.evidence_steps),
            recommended_action=base_report.recommended_action,
            rationale=f"audit call {self.calls}",
        )


class AlwaysAllowJudge:
    def review(self, events, base_report):
        return JudgeDecision(
            recommended_action="allow",
            rationale="force allow for divergence test",
        )


def test_evaluate_records_audit_all_uses_judge_for_every_case():
    records = [
        BenchmarkRecord(
            sample_path=ROOT / "data" / "samples" / "normal_refactor.jsonl",
            expected_action="allow",
            task_family="benign_refactor",
        ),
        BenchmarkRecord(
            sample_path=ROOT / "data" / "samples" / "sensitive_exfiltration.jsonl",
            expected_action="block",
            task_family="sensitive_exfiltration",
        ),
        BenchmarkRecord(
            sample_path=ROOT / "data" / "samples" / "supply_chain_manifest_write.jsonl",
            expected_action="require_review",
            task_family="supply_chain_manifest_write",
        ),
    ]
    judge = CountingJudge()

    report = evaluate_records(records, judge=judge, judge_mode="audit-all")

    assert report["detector_mode"] == "rules+judge-audit-all"
    assert judge.calls == 3
    assert report["judge_invocation_count"] == 3
    assert [row["judge_rationale"] for row in report["records"]] == [
        "audit call 1",
        "audit call 2",
        "audit call 3",
    ]


def test_audit_all_records_base_action_before_judge_override():
    records = [
        BenchmarkRecord(
            sample_path=ROOT / "data" / "samples" / "sensitive_exfiltration.jsonl",
            expected_action="block",
            task_family="sensitive_exfiltration",
        )
    ]

    report = evaluate_records(records, judge=AlwaysAllowJudge(), judge_mode="audit-all")

    row = report["records"][0]
    assert row["base_predicted_action"] == "block"
    assert row["predicted_action"] == "allow"
    assert row["judge_recommended_action"] == "allow"
    assert report["base_action_confusion"]["block"]["allow"] == 1
