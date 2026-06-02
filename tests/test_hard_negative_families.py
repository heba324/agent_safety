from pathlib import Path

from agent_risk.benchmark import load_records
from agent_risk.detector import BehaviorChainDetector
from agent_risk.generator import generate_benchmark


def test_env_example_read_and_localhost_request_are_allowed(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    env_example = (tmp_path / "samples" / "benign_env_example_read-001.jsonl").read_text(
        encoding="utf-8"
    )
    local_api = (tmp_path / "samples" / "benign_local_api_test-001.jsonl").read_text(
        encoding="utf-8"
    )

    detector = BehaviorChainDetector()

    assert detector.detect_jsonl(env_example).recommended_action == "allow"
    assert detector.detect_jsonl(local_api).recommended_action == "allow"


def test_prompt_injection_to_exfiltration_is_blocked(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    payload = (
        tmp_path / "samples" / "prompt_injection_to_exfiltration-001.jsonl"
    ).read_text(encoding="utf-8")
    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.recommended_action == "block"
    assert report.overall.risk_types == ["prompt_injection_to_unsafe_action"]
    assert [finding.rule_id for finding in report.findings] == [
        "prompt_injection.compliance",
        "file.sensitive_secret",
        "network.external_upload",
    ]


def test_generated_manifest_includes_hard_negative_and_exfiltration_families(
    tmp_path: Path,
):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=2,
    )

    records = load_records(tmp_path / "manifest.jsonl")
    families = {record.task_family for record in records}

    assert "benign_env_example_read" in families
    assert "benign_local_api_test" in families
    assert "prompt_injection_to_exfiltration" in families
    assert "stealth_http_exfiltration" in families
    assert "issue_comment_exfiltration" in families
    assert "git_remote_exfiltration" in families
    assert "obfuscated_prompt_injection_to_exfiltration" in families
    assert len(records) == 32
