import json
from typing import List

from agent_risk.detector import BehaviorChainDetector, DetectionReport
from agent_risk.judge import LLMJudge
from agent_risk.schema import AgentEvent


class CascadeDetector:
    def __init__(self, judge: LLMJudge) -> None:
        self._base_detector = BehaviorChainDetector()
        self._judge = judge

    def detect_jsonl(self, payload: str) -> DetectionReport:
        events = [
            AgentEvent.from_dict(json.loads(line))
            for line in payload.splitlines()
            if line.strip()
        ]
        return self.detect_events(events)

    def detect_events(self, events: List[AgentEvent]) -> DetectionReport:
        base_report = self._base_detector.detect_events(events)
        if base_report.recommended_action != "require_review":
            return base_report

        decision = self._judge.review(events, base_report)
        return DetectionReport(
            overall=base_report.overall,
            findings=base_report.findings,
            recommended_action=decision.recommended_action,
            judge_decision=decision,
        )
