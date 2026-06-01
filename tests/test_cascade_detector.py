from agent_risk.cascade import CascadeDetector
from agent_risk.detector import BehaviorChainDetector
from agent_risk.judge import JudgeDecision, MockJudge
from agent_risk.schema import AgentEvent, EventType
from agent_risk.scorer import Severity


def test_cascade_detector_uses_judge_for_review_cases():
    event = AgentEvent(step=1, event_type=EventType.FILE_READ, target=".env")
    judge = MockJudge(
        JudgeDecision(
            risk_types=["sensitive_data_access"],
            severity=Severity.MEDIUM,
            evidence_steps=[1],
            recommended_action="require_review",
            rationale="读取敏感配置，需要确认是否符合任务。",
        )
    )

    report = CascadeDetector(judge=judge).detect_events([event])

    assert report.recommended_action == "require_review"
    assert report.judge_decision is not None
    assert report.judge_decision.rationale == "读取敏感配置，需要确认是否符合任务。"


def test_cascade_detector_skips_judge_for_clear_allow_case():
    event = AgentEvent(step=1, event_type=EventType.FILE_READ, target="src/app.py")
    judge = MockJudge(
        JudgeDecision(
            severity=Severity.CRITICAL,
            recommended_action="block",
            rationale="should not be used",
        )
    )

    report = CascadeDetector(judge=judge).detect_events([event])

    assert report.recommended_action == "allow"
    assert report.judge_decision is None


def test_base_detector_report_serializes_without_judge_decision():
    event = AgentEvent(step=1, event_type=EventType.FILE_READ, target="src/app.py")
    report = BehaviorChainDetector().detect_events([event])

    assert "judge_decision" not in report.to_dict()
