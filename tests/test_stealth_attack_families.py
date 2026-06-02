from pathlib import Path

from agent_risk.benchmark import load_records
from agent_risk.detector import BehaviorChainDetector
from agent_risk.generator import generate_benchmark


def _payload(tmp_path: Path, sample_name: str) -> str:
    return (tmp_path / "samples" / sample_name).read_text(encoding="utf-8")


def test_stealth_http_exfiltration_without_upload_keywords_is_blocked(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    report = BehaviorChainDetector().detect_jsonl(
        _payload(tmp_path, "stealth_http_exfiltration-001.jsonl")
    )

    assert report.recommended_action == "block"
    assert "sensitive_data_exfiltration" in report.overall.risk_types


def test_issue_comment_exfiltration_is_blocked(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    report = BehaviorChainDetector().detect_jsonl(
        _payload(tmp_path, "issue_comment_exfiltration-001.jsonl")
    )

    assert report.recommended_action == "block"
    assert "sensitive_data_exfiltration" in report.overall.risk_types


def test_git_remote_exfiltration_is_blocked(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    report = BehaviorChainDetector().detect_jsonl(
        _payload(tmp_path, "git_remote_exfiltration-001.jsonl")
    )

    assert report.recommended_action == "block"
    assert any(finding.rule_id == "network.git_remote_exfiltration" for finding in report.findings)


def test_obfuscated_prompt_injection_to_exfiltration_is_blocked(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    report = BehaviorChainDetector().detect_jsonl(
        _payload(tmp_path, "obfuscated_prompt_injection_to_exfiltration-001.jsonl")
    )

    assert report.recommended_action == "block"
    assert report.overall.risk_types == ["prompt_injection_to_unsafe_action"]


def test_manifest_contains_stealth_attack_families(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    families = {record.task_family for record in load_records(tmp_path / "manifest.jsonl")}

    assert "stealth_http_exfiltration" in families
    assert "issue_comment_exfiltration" in families
    assert "git_remote_exfiltration" in families
    assert "obfuscated_prompt_injection_to_exfiltration" in families
