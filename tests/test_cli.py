import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(sample_name: str):
    sample_path = ROOT / "data" / "samples" / sample_name
    completed = subprocess.run(
        [sys.executable, "-m", "agent_risk.cli", str(sample_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return completed


def test_cli_outputs_json_report_for_high_risk_chain():
    completed = run_cli("sensitive_exfiltration.jsonl")

    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["recommended_action"] == "block"
    assert report["overall"]["severity"] == "high"
    assert report["overall"]["risk_types"] == ["sensitive_data_exfiltration"]
    assert [finding["rule_id"] for finding in report["findings"]] == [
        "file.sensitive_secret",
        "network.external_upload",
    ]


def test_cli_returns_zero_for_allowed_chain():
    completed = run_cli("normal_refactor.jsonl")

    assert completed.returncode == 0
    report = json.loads(completed.stdout)
    assert report["recommended_action"] == "allow"
    assert report["findings"] == []


def test_cli_accepts_rules_only_judge_mode():
    sample_path = ROOT / "data" / "samples" / "normal_refactor.jsonl"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_risk.cli",
            str(sample_path),
            "--judge",
            "rules-only",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["recommended_action"] == "allow"
