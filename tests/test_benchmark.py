from pathlib import Path

from agent_risk.benchmark import BenchmarkRecord, evaluate_records


ROOT = Path(__file__).resolve().parents[1]


def test_evaluate_records_computes_action_and_unsafe_metrics():
    records = [
        BenchmarkRecord(
            sample_path=ROOT / "data" / "samples" / "normal_refactor.jsonl",
            expected_action="allow",
            expected_risk_types=[],
            task_family="benign_refactor",
        ),
        BenchmarkRecord(
            sample_path=ROOT / "data" / "samples" / "sensitive_exfiltration.jsonl",
            expected_action="block",
            expected_risk_types=["sensitive_data_exfiltration"],
            task_family="sensitive_exfiltration",
        ),
        BenchmarkRecord(
            sample_path=ROOT / "data" / "samples" / "supply_chain_manifest_write.jsonl",
            expected_action="require_review",
            expected_risk_types=["supply_chain.dependency_manifest_write"],
            task_family="supply_chain_manifest_write",
        ),
    ]

    report = evaluate_records(records)

    assert report["total"] == 3
    assert report["action_accuracy"] == 1.0
    assert report["unsafe_precision"] == 1.0
    assert report["unsafe_recall"] == 1.0
    assert report["unsafe_f1"] == 1.0
    assert [row["predicted_action"] for row in report["records"]] == [
        "allow",
        "block",
        "require_review",
    ]
    assert report["family_metrics"]["benign_refactor"]["action_accuracy"] == 1.0
    assert report["family_metrics"]["sensitive_exfiltration"]["unsafe_recall"] == 1.0


def test_benchmark_record_from_dict_resolves_relative_sample_path():
    record = BenchmarkRecord.from_dict(
        {
            "sample_path": "data/samples/normal_refactor.jsonl",
            "sample_id": "benign-001",
            "task_family": "benign_refactor",
            "expected_action": "allow",
            "expected_risk_types": [],
            "evidence_steps": [],
            "attack_source": "none",
            "trust_boundary": "none",
            "data_asset": "source_code",
        },
        root=ROOT,
    )

    assert record.sample_path == ROOT / "data" / "samples" / "normal_refactor.jsonl"
    assert record.sample_id == "benign-001"
    assert record.task_family == "benign_refactor"
    assert record.expected_action == "allow"
    assert record.data_asset == "source_code"
