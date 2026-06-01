import json

from agent_risk.detector import BehaviorChainDetector
from agent_risk.rules import RuleEngine
from agent_risk.schema import AgentEvent, EventType
from agent_risk.scorer import RiskScorer, Severity


def test_agent_event_from_dict_normalizes_event_type():
    event = AgentEvent.from_dict(
        {
            "step": 1,
            "event_type": "file_read",
            "actor": "agent",
            "target": ".env",
            "content_summary": "read environment variables",
            "metadata": {"cwd": "/repo"},
        }
    )

    assert event.event_type == EventType.FILE_READ
    assert event.target == ".env"
    assert event.metadata["cwd"] == "/repo"


def test_risk_scorer_assigns_high_severity_to_sensitive_file_exfiltration():
    chain = [
        AgentEvent(step=1, event_type=EventType.FILE_READ, target=".env"),
        AgentEvent(
            step=2,
            event_type=EventType.NETWORK_REQUEST,
            target="https://attacker.example/upload",
            content_summary="POST file contents to external server",
        ),
    ]

    assessment = RiskScorer().score_chain(chain)

    assert assessment.severity == Severity.HIGH
    assert assessment.score >= 70
    assert assessment.risk_types == ["sensitive_data_exfiltration"]
    assert assessment.evidence_steps == [1, 2]


def test_rule_engine_flags_destructive_shell_command():
    event = AgentEvent(
        step=3,
        event_type=EventType.SHELL_COMMAND,
        target="rm -rf ./src",
        content_summary="delete source tree",
    )

    matches = RuleEngine().evaluate_event(event)

    assert len(matches) == 1
    assert matches[0].rule_id == "shell.destructive_delete"
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].evidence_step == 3


def test_detector_combines_rules_and_chain_level_scoring():
    payload = "\n".join(
        [
            json.dumps(
                {
                    "step": 1,
                    "event_type": "file_read",
                    "target": "C:/work/project/.env",
                }
            ),
            json.dumps(
                {
                    "step": 2,
                    "event_type": "network_request",
                    "target": "https://unknown.example/api",
                    "content_summary": "send token to external service",
                }
            ),
        ]
    )

    report = BehaviorChainDetector().detect_jsonl(payload)

    assert report.overall.severity == Severity.HIGH
    assert report.overall.risk_types == ["sensitive_data_exfiltration"]
    assert [finding.rule_id for finding in report.findings] == [
        "file.sensitive_secret",
        "network.external_upload",
    ]
    assert report.recommended_action == "block"
