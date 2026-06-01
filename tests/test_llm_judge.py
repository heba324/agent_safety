import json

from agent_risk.detector import BehaviorChainDetector
from agent_risk.judge import (
    JudgeDecision,
    MockJudge,
    OpenAICompatibleJudge,
    build_judge_prompt,
    parse_judge_json,
)
from agent_risk.schema import AgentEvent, EventType
from agent_risk.scorer import Severity


def test_build_judge_prompt_contains_events_and_rules():
    event = AgentEvent(
        step=1,
        event_type=EventType.FILE_READ,
        target=".env",
        content_summary="Read env file.",
    )
    report = BehaviorChainDetector().detect_events([event])

    prompt = build_judge_prompt([event], report.findings, report.overall)

    assert "只输出一个 JSON 对象" in prompt
    assert '"event_type": "file_read"' in prompt
    assert "file.sensitive_secret" in prompt


def test_parse_judge_json_extracts_json_from_markdown_block():
    text = """
    ```json
    {
      "risk_types": ["sensitive_data_access"],
      "severity": "medium",
      "evidence_steps": [1],
      "recommended_action": "require_review",
      "rationale": "读取敏感文件但没有外传。"
    }
    ```
    """

    decision = parse_judge_json(text)

    assert decision.severity == Severity.MEDIUM
    assert decision.recommended_action == "require_review"
    assert decision.evidence_steps == [1]


def test_mock_judge_can_override_review_to_allow_for_benign_context():
    event = AgentEvent(
        step=1,
        event_type=EventType.FILE_READ,
        target=".env",
        content_summary="Read local env only for unit test.",
    )
    base_report = BehaviorChainDetector().detect_events([event])
    judge = MockJudge(
        JudgeDecision(
            risk_types=[],
            severity=Severity.LOW,
            evidence_steps=[],
            recommended_action="allow",
            rationale="本地测试上下文，无外传。",
        )
    )

    decision = judge.review([event], base_report)

    assert decision.recommended_action == "allow"
    assert decision.severity == Severity.LOW


def test_openai_compatible_judge_parses_chat_completion_response(monkeypatch):
    captured = {}

    def fake_transport(url, headers, payload, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["payload"] = payload
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "risk_types": ["sensitive_data_access"],
                                "severity": "medium",
                                "evidence_steps": [1],
                                "recommended_action": "require_review",
                                "rationale": "需要人工确认。",
                            }
                        )
                    }
                }
            ]
        }

    judge = OpenAICompatibleJudge(
        api_key="test-key",
        base_url="https://api.example/v1",
        model="Qwen/Qwen3-8B",
        transport=fake_transport,
    )
    event = AgentEvent(step=1, event_type=EventType.FILE_READ, target=".env")
    base_report = BehaviorChainDetector().detect_events([event])

    decision = judge.review([event], base_report)

    assert decision.recommended_action == "require_review"
    assert captured["url"] == "https://api.example/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["payload"]["model"] == "Qwen/Qwen3-8B"
