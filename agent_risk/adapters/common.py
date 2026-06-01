import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List


@dataclass(frozen=True)
class AdaptedSample:
    sample_id: str
    task_family: str
    events: List[dict]
    expected_action: str
    expected_risk_types: List[str] = field(default_factory=list)
    evidence_steps: List[int] = field(default_factory=list)
    attack_source: str = "unknown"
    trust_boundary: str = "unknown"
    data_asset: str = "unknown"
    label_status: str = "weak"
    source_dataset: str = "unknown"

    def manifest_row(self, sample_path: Path) -> dict:
        return {
            "sample_id": self.sample_id,
            "sample_path": str(sample_path),
            "task_family": self.task_family,
            "expected_action": self.expected_action,
            "expected_risk_types": self.expected_risk_types,
            "evidence_steps": self.evidence_steps,
            "attack_source": self.attack_source,
            "trust_boundary": self.trust_boundary,
            "data_asset": self.data_asset,
            "label_status": self.label_status,
            "source_dataset": self.source_dataset,
        }


def write_adapted_samples(
    samples: Iterable[AdaptedSample],
    output_dir: Path,
    manifest_path: Path,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    count = 0
    for sample in samples:
        sample_path = output_dir / f"{_safe_name(sample.sample_id)}.jsonl"
        sample_path.write_text(
            "\n".join(
                json.dumps(event, ensure_ascii=False) for event in sample.events
            )
            + "\n",
            encoding="utf-8",
        )
        rows.append(sample.manifest_row(sample_path))
        count += 1

    manifest_path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )
    return {
        "sample_count": count,
        "output_dir": str(output_dir),
        "manifest_path": str(manifest_path),
    }


def _safe_name(value: str) -> str:
    return (
        value.replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(" ", "_")
    )


def text_of(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
