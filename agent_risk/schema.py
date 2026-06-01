from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class EventType(str, Enum):
    MODEL_MESSAGE = "model_message"
    TOOL_CALL = "tool_call"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SHELL_COMMAND = "shell_command"
    NETWORK_REQUEST = "network_request"


@dataclass(frozen=True)
class AgentEvent:
    step: int
    event_type: EventType
    actor: str = "agent"
    target: str = ""
    content_summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    destination: Optional[str] = None

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "AgentEvent":
        return cls(
            step=int(payload["step"]),
            event_type=EventType(payload["event_type"]),
            actor=payload.get("actor", "agent"),
            target=payload.get("target", ""),
            content_summary=payload.get("content_summary", ""),
            metadata=dict(payload.get("metadata", {})),
            source=payload.get("source"),
            destination=payload.get("destination"),
        )
