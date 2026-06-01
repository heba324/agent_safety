from typing import List

from agent_risk.adapters.common import AdaptedSample, text_of


def adapt_swe_hero_record(record: dict, index: int) -> AdaptedSample:
    instance_id = record.get("instance_id") or record.get("id") or f"{index:06d}"
    trajectory = record.get("trajectory") or record.get("messages") or []

    events = []
    for step, item in enumerate(trajectory, start=1):
        events.append(_event_from_trajectory_item(step, item))

    return AdaptedSample(
        sample_id=f"swe_hero-{instance_id}",
        task_family="public_swe_hero",
        events=events,
        expected_action="allow",
        expected_risk_types=[],
        evidence_steps=[],
        attack_source="none",
        trust_boundary="none",
        data_asset="source_code",
        label_status="weak_benign_candidate",
        source_dataset="SWE-Hero OpenHands trajectories",
    )


def _event_from_trajectory_item(step: int, item: dict) -> dict:
    action = str(item.get("action") or item.get("tool_name") or "").lower()
    args = item.get("args") or item.get("arguments") or {}
    content = text_of(item.get("content") or item.get("observation") or item)

    if action in ("read", "read_file", "open_file"):
        return _event(step, "file_read", _arg(args, "path", "file_path"), content)
    if action in ("write", "write_file", "edit", "edit_file"):
        return _event(step, "file_write", _arg(args, "path", "file_path"), content)
    if action in ("run", "run_command", "bash", "shell", "terminal"):
        return _event(step, "shell_command", _arg(args, "command", "cmd"), content)

    lowered = content.lower()
    if "python -m pytest" in lowered or "pytest " in lowered:
        return _event(step, "shell_command", _extract_command(content), content)
    if "read" in lowered and ".py" in lowered:
        return _event(step, "file_read", _extract_path(content), content)
    if "write" in lowered and ".py" in lowered:
        return _event(step, "file_write", _extract_path(content), content)

    return _event(step, "model_message", item.get("role", "message"), content)


def _event(step: int, event_type: str, target: str, content_summary: str) -> dict:
    return {
        "step": step,
        "event_type": event_type,
        "target": target or "",
        "content_summary": content_summary[:500],
    }


def _arg(args: object, *names: str) -> str:
    if not isinstance(args, dict):
        return text_of(args)
    for name in names:
        if name in args:
            return text_of(args[name])
    return text_of(args)


def _extract_command(content: str) -> str:
    for line in content.splitlines():
        if "pytest" in line:
            return line.strip("` ")
    return content[:120]


def _extract_path(content: str) -> str:
    tokens: List[str] = content.replace("`", " ").replace('"', " ").split()
    for token in tokens:
        if "." in token and "/" in token:
            return token.strip(".,:;")
    for token in tokens:
        if token.endswith(".py"):
            return token.strip(".,:;")
    return ""
