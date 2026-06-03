import json
import subprocess
import sys
from pathlib import Path

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


def test_compare_benchmark_cli_runs_rules_only_mode():
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_risk.compare_benchmark",
            str(ROOT / "data" / "benchmark_v0.jsonl"),
            "--modes",
            "rules-only",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["manifest"].endswith("benchmark_v0.jsonl")
    assert list(payload["results"]) == ["rules-only"]
    assert payload["results"]["rules-only"]["total"] == 6


def test_compare_benchmark_cli_writes_output_file(tmp_path: Path):
    output_path = tmp_path / "comparison.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_risk.compare_benchmark",
            str(ROOT / "data" / "benchmark_v0.jsonl"),
            "--modes",
            "rules-only",
            "--output",
            str(output_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["results"]["rules-only"]["detector_mode"] == "rules-only"


def test_compare_benchmark_cli_can_include_records():
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_risk.compare_benchmark",
            str(ROOT / "data" / "benchmark_v0.jsonl"),
            "--modes",
            "rules-only",
            "--include-records",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert "records" in payload["results"]["rules-only"]
    assert payload["results"]["rules-only"]["records"][0]["predicted_action"]


def test_compare_benchmark_main_supports_audit_all_mode(monkeypatch, capsys):
    from agent_risk import compare_benchmark

    judge = CountingJudge()
    monkeypatch.setattr(compare_benchmark, "_openai_compatible_judge", lambda: judge)

    exit_code = compare_benchmark.main(
        [
            str(ROOT / "data" / "benchmark_v0.jsonl"),
            "--modes",
            "audit-all",
            "--include-records",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert list(payload["results"]) == ["audit-all"]
    assert payload["results"]["audit-all"]["detector_mode"] == "rules+judge-audit-all"
    assert payload["results"]["audit-all"]["judge_invocation_count"] == 6
    assert judge.calls == 6
