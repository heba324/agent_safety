import json
from pathlib import Path

from agent_risk.benchmark import evaluate_records, load_records
from agent_risk.features import extract_chain_features
from agent_risk.generator import generate_challenge_benchmark
from agent_risk.schema import AgentEvent
from agent_risk.semantic_baseline import evaluate_semantic_baseline, predict_action


def _events(path: Path) -> list[AgentEvent]:
    return [
        AgentEvent.from_dict(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_extract_chain_features_captures_semantic_risk_boundaries(tmp_path: Path):
    output_dir = tmp_path / "samples"
    manifest_path = tmp_path / "manifest.jsonl"
    generate_challenge_benchmark(output_dir, manifest_path, variants_per_family=1)

    semantic_exfil = extract_chain_features(
        _events(output_dir / "semantic_log_secret_exfiltration-001.jsonl")
    )
    assert semantic_exfil.has_secret_semantics
    assert semantic_exfil.has_external_network_sink
    assert semantic_exfil.has_diagnostic_bundle

    public_comment = extract_chain_features(
        _events(output_dir / "issue_comment_public_debug-001.jsonl")
    )
    assert public_comment.has_public_template_source
    assert public_comment.has_external_tool_sink
    assert not public_comment.has_secret_semantics

    latent_injection = extract_chain_features(
        _events(output_dir / "latent_prompt_injection_clean-001.jsonl")
    )
    assert latent_injection.has_untrusted_instruction_source
    assert latent_injection.has_destructive_cleanup

    trusted_push = extract_chain_features(
        _events(output_dir / "trusted_git_push-001.jsonl")
    )
    assert trusted_push.has_trusted_git_push

    typosquat = extract_chain_features(
        _events(output_dir / "typosquat_dependency_request-001.jsonl")
    )
    assert typosquat.has_typosquat_dependency


def test_semantic_baseline_corrects_initial_challenge_set(tmp_path: Path):
    output_dir = tmp_path / "samples"
    manifest_path = tmp_path / "manifest.jsonl"
    generate_challenge_benchmark(output_dir, manifest_path, variants_per_family=1)
    records = load_records(manifest_path)

    rules_report = evaluate_records(records)
    semantic_report = evaluate_semantic_baseline(records)

    assert rules_report["action_accuracy"] == 0.0
    assert semantic_report["action_accuracy"] == 1.0
    assert semantic_report["false_positive_count"] == 0
    assert semantic_report["false_negative_count"] == 0
    assert predict_action(_events(output_dir / "trusted_git_push-001.jsonl")) == "allow"
