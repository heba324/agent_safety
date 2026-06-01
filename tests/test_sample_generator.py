import json
from pathlib import Path

from agent_risk.benchmark import load_records
from agent_risk.generator import generate_benchmark


def test_generate_benchmark_writes_samples_and_manifest(tmp_path: Path):
    output_dir = tmp_path / "generated"
    manifest_path = tmp_path / "benchmark_generated.jsonl"

    summary = generate_benchmark(
        output_dir=output_dir,
        manifest_path=manifest_path,
        variants_per_family=2,
    )

    assert summary["families"] == [
        "benign_refactor",
        "benign_env_example_read",
        "benign_local_api_test",
        "sensitive_exfiltration",
        "prompt_injection_to_delete",
        "prompt_injection_to_exfiltration",
        "supply_chain_manifest_write",
        "sandbox_escape_attempt",
    ]
    assert summary["sample_count"] == 16
    assert manifest_path.exists()
    assert len(list(output_dir.glob("*.jsonl"))) == 16

    records = load_records(manifest_path)
    assert len(records) == 16
    assert any(record.expected_action == "block" for record in records)
    assert any(record.expected_action == "require_review" for record in records)
    assert sum(record.expected_action == "allow" for record in records) == 6


def test_generated_manifest_contains_annotation_fields(tmp_path: Path):
    output_dir = tmp_path / "generated"
    manifest_path = tmp_path / "benchmark_generated.jsonl"

    generate_benchmark(output_dir, manifest_path, variants_per_family=1)

    rows = [
        json.loads(line)
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
    ]

    assert rows[0]["sample_id"] == "benign_refactor-001"
    assert rows[0]["task_family"] == "benign_refactor"
    assert rows[0]["attack_source"] == "none"
    assert rows[0]["trust_boundary"] == "none"
    assert rows[0]["data_asset"] == "source_code"
    rows_by_family = {row["task_family"]: row for row in rows}
    assert rows_by_family["sensitive_exfiltration"]["expected_action"] == "block"
    assert rows_by_family["sensitive_exfiltration"]["evidence_steps"] == [2, 3]
    assert rows_by_family["benign_env_example_read"]["expected_action"] == "allow"
    assert (
        rows_by_family["prompt_injection_to_exfiltration"]["expected_action"]
        == "block"
    )
