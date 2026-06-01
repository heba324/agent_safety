import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_import_public_cli_converts_swe_hero_jsonl(tmp_path: Path):
    source_path = tmp_path / "swe_hero.jsonl"
    source_path.write_text(
        json.dumps(
            {
                "instance_id": "repo-issue-1",
                "trajectory": [
                    {"role": "user", "content": "Fix typo."},
                    {"role": "assistant", "action": "read", "args": {"path": "a.py"}},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    output_dir = tmp_path / "samples"
    manifest_path = tmp_path / "manifest.jsonl"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_risk.import_public",
            "--dataset",
            "swe_hero",
            "--input",
            str(source_path),
            "--output-dir",
            str(output_dir),
            "--manifest",
            str(manifest_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    summary = json.loads(completed.stdout)
    assert summary["sample_count"] == 1
    assert manifest_path.exists()
    assert len(list(output_dir.glob("*.jsonl"))) == 1


def test_import_public_cli_accepts_utf8_bom_jsonl(tmp_path: Path):
    source_path = tmp_path / "swe_hero_bom.jsonl"
    source_path.write_text(
        json.dumps({"instance_id": "bom-1", "trajectory": []}) + "\n",
        encoding="utf-8-sig",
    )
    manifest_path = tmp_path / "manifest.jsonl"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_risk.import_public",
            "--dataset",
            "swe_hero",
            "--input",
            str(source_path),
            "--output-dir",
            str(tmp_path / "samples"),
            "--manifest",
            str(manifest_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout)["sample_count"] == 1
