from pathlib import Path

from agent_risk.benchmark import evaluate_records, load_records
from agent_risk.generator import generate_challenge_benchmark


def test_generate_challenge_benchmark_writes_semantic_gap_families(tmp_path: Path):
    output_dir = tmp_path / "challenge_samples"
    manifest_path = tmp_path / "challenge_benchmark.jsonl"

    summary = generate_challenge_benchmark(
        output_dir=output_dir,
        manifest_path=manifest_path,
        variants_per_family=1,
    )

    assert summary["families"] == [
        "semantic_log_secret_exfiltration",
        "trusted_git_push",
        "issue_comment_public_debug",
        "latent_prompt_injection_clean",
        "typosquat_dependency_request",
    ]
    assert summary["sample_count"] == 5
    assert len(list(output_dir.glob("*.jsonl"))) == 5

    records = load_records(manifest_path)
    assert {record.expected_action for record in records} == {"allow", "block"}
    assert {record.task_family for record in records} == set(summary["families"])


def test_challenge_benchmark_exposes_rules_only_disagreements(tmp_path: Path):
    output_dir = tmp_path / "challenge_samples"
    manifest_path = tmp_path / "challenge_benchmark.jsonl"
    generate_challenge_benchmark(output_dir, manifest_path, variants_per_family=1)

    report = evaluate_records(load_records(manifest_path))

    assert report["total"] == 5
    assert report["action_accuracy"] < 1.0
    assert report["false_positive_count"] >= 1
    assert report["false_negative_count"] >= 1
