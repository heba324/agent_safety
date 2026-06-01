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
