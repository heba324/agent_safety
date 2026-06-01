from pathlib import Path

from agent_risk.benchmark import load_records
from agent_risk.detector import BehaviorChainDetector
from agent_risk.generator import generate_benchmark


def test_sensitive_read_without_exfiltration_requires_review(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    payload = (tmp_path / "samples" / "sensitive_read_no_exfil-001.jsonl").read_text(
        encoding="utf-8"
    )
    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.recommended_action == "require_review"
    assert report.findings[0].rule_id == "file.sensitive_secret"


def test_prompt_injection_ignored_is_allowed(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    payload = (
        tmp_path / "samples" / "benign_prompt_injection_ignored-001.jsonl"
    ).read_text(encoding="utf-8")
    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.recommended_action == "allow"
    assert report.findings == []


def test_legitimate_external_api_call_requires_review_not_block(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    payload = (
        tmp_path / "samples" / "legitimate_external_api_call-001.jsonl"
    ).read_text(encoding="utf-8")
    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.recommended_action == "allow"
    assert report.findings == []


def test_high_risk_postinstall_supply_chain_is_blocked(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    payload = (
        tmp_path / "samples" / "supply_chain_postinstall-001.jsonl"
    ).read_text(encoding="utf-8")
    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.recommended_action == "block"
    assert [finding.rule_id for finding in report.findings] == [
        "supply_chain.dependency_manifest_write",
        "supply_chain.postinstall_script",
    ]


def test_manifest_contains_ambiguous_families(tmp_path: Path):
    generate_benchmark(
        output_dir=tmp_path / "samples",
        manifest_path=tmp_path / "manifest.jsonl",
        variants_per_family=1,
    )

    families = {record.task_family for record in load_records(tmp_path / "manifest.jsonl")}

    assert "sensitive_read_no_exfil" in families
    assert "benign_prompt_injection_ignored" in families
    assert "legitimate_external_api_call" in families
    assert "supply_chain_postinstall" in families
