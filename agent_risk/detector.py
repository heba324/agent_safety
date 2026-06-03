import json
from dataclasses import dataclass, field
from typing import List

from agent_risk.rules import RuleEngine, RuleMatch
from agent_risk.schema import AgentEvent
from agent_risk.scorer import RiskAssessment, RiskScorer, Severity


@dataclass(frozen=True)
class DetectionReport:
    overall: RiskAssessment
    findings: List[RuleMatch] = field(default_factory=list)
    recommended_action: str = "allow"
    judge_decision: object = None
    base_recommended_action: str | None = None

    def to_dict(self) -> dict:
        payload = {
            "overall": {
                "score": self.overall.score,
                "severity": self.overall.severity.value,
                "risk_types": self.overall.risk_types,
                "evidence_steps": self.overall.evidence_steps,
            },
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "message": finding.message,
                    "evidence_step": finding.evidence_step,
                }
                for finding in self.findings
            ],
            "recommended_action": self.recommended_action,
        }
        if self.base_recommended_action is not None:
            payload["base_recommended_action"] = self.base_recommended_action
        if self.judge_decision is not None:
            payload["judge_decision"] = {
                "risk_types": self.judge_decision.risk_types,
                "severity": self.judge_decision.severity.value,
                "evidence_steps": self.judge_decision.evidence_steps,
                "recommended_action": self.judge_decision.recommended_action,
                "rationale": self.judge_decision.rationale,
            }
        return payload


class BehaviorChainDetector:
    def __init__(self) -> None:
        self._rules = RuleEngine()
        self._scorer = RiskScorer()

    def detect_jsonl(self, payload: str) -> DetectionReport:
        events = [
            AgentEvent.from_dict(json.loads(line))
            for line in payload.splitlines()
            if line.strip()
        ]
        return self.detect_events(events)

    def detect_events(self, events: List[AgentEvent]) -> DetectionReport:
        findings: List[RuleMatch] = []
        for event in events:
            findings.extend(self._rules.evaluate_event(event))

        overall = self._scorer.score_chain(events)
        return DetectionReport(
            overall=overall,
            findings=findings,
            recommended_action=self._recommend_action(overall, findings),
        )

    @staticmethod
    def _recommend_action(
        overall: RiskAssessment, findings: List[RuleMatch]
    ) -> str:
        if overall.severity == Severity.CRITICAL:
            return "block"
        if any(finding.severity == Severity.CRITICAL for finding in findings):
            return "block"
        if overall.severity == Severity.HIGH:
            return "block"
        if findings or overall.severity == Severity.MEDIUM:
            return "require_review"
        return "allow"
