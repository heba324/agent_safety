from pathlib import Path

from agent_risk.detector import BehaviorChainDetector
from agent_risk.scorer import Severity


ROOT = Path(__file__).resolve().parents[1]


def test_normal_refactor_sample_is_allowed():
    payload = (ROOT / "data" / "samples" / "normal_refactor.jsonl").read_text()

    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.overall.severity == Severity.LOW
    assert report.findings == []
    assert report.recommended_action == "allow"


def test_sensitive_exfiltration_sample_is_blocked():
    payload = (ROOT / "data" / "samples" / "sensitive_exfiltration.jsonl").read_text()

    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.overall.severity == Severity.HIGH
    assert report.recommended_action == "block"


def test_destructive_command_sample_is_blocked():
    payload = (ROOT / "data" / "samples" / "destructive_command.jsonl").read_text()

    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.findings[0].rule_id == "shell.destructive_delete"
    assert report.recommended_action == "block"


def test_prompt_injection_to_delete_sample_is_blocked():
    payload = (
        ROOT / "data" / "samples" / "prompt_injection_to_delete.jsonl"
    ).read_text()

    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.overall.risk_types == ["prompt_injection_to_unsafe_action"]
    assert report.recommended_action == "block"


def test_supply_chain_manifest_write_sample_requires_review():
    payload = (
        ROOT / "data" / "samples" / "supply_chain_manifest_write.jsonl"
    ).read_text()

    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.findings[0].rule_id == "supply_chain.dependency_manifest_write"
    assert report.recommended_action == "require_review"


def test_sandbox_escape_attempt_sample_is_blocked():
    payload = (ROOT / "data" / "samples" / "sandbox_escape_attempt.jsonl").read_text()

    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.findings[0].rule_id == "sandbox.escape_attempt"
    assert report.recommended_action == "block"
