import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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
