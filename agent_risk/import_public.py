import argparse
import json
from pathlib import Path
from typing import Callable, List, Sequence

from agent_risk.adapters.agentdojo import adapt_agentdojo_record
from agent_risk.adapters.common import AdaptedSample, write_adapted_samples
from agent_risk.adapters.swe_hero import adapt_swe_hero_record


Adapter = Callable[[dict, int], AdaptedSample]


_ADAPTERS: dict[str, Adapter] = {
    "swe_hero": adapt_swe_hero_record,
    "agentdojo": adapt_agentdojo_record,
    "toolemu": adapt_agentdojo_record,
}


def import_public_dataset(
    dataset: str,
    input_path: Path,
    output_dir: Path,
    manifest_path: Path,
    limit: int | None = None,
) -> dict:
    adapter = _ADAPTERS[dataset]
    samples: List[AdaptedSample] = []
    for index, record in enumerate(_read_jsonl(input_path), start=1):
        if limit is not None and index > limit:
            break
        samples.append(adapter(record, index))
    summary = write_adapted_samples(samples, output_dir, manifest_path)
    summary["dataset"] = dataset
    return summary


def _read_jsonl(path: Path):
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.strip():
            yield json.loads(line)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-risk-import-public",
        description="Convert exported public dataset JSONL into behavior-chain samples.",
    )
    parser.add_argument("--dataset", choices=sorted(_ADAPTERS), required=True)
    parser.add_argument("--input", required=True, help="Source JSONL file.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--limit", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = import_public_dataset(
        dataset=args.dataset,
        input_path=Path(args.input),
        output_dir=Path(args.output_dir),
        manifest_path=Path(args.manifest),
        limit=args.limit,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
