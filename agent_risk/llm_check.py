import json
from typing import Sequence

from agent_risk.config import load_env_file
from agent_risk.judge import OpenAICompatibleJudge


def main(argv: Sequence[str] | None = None) -> int:
    try:
        load_env_file()
        judge = OpenAICompatibleJudge.from_env()
        decision = judge.review([], _empty_base_report())
        print(
            json.dumps(
                {
                    "ok": True,
                    "model": judge.model,
                    "base_url": judge.base_url,
                    "decision": {
                        "recommended_action": decision.recommended_action,
                        "severity": decision.severity.value,
                        "risk_types": decision.risk_types,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1


def _empty_base_report():
    from agent_risk.detector import DetectionReport
    from agent_risk.scorer import RiskAssessment, Severity

    return DetectionReport(overall=RiskAssessment(score=0, severity=Severity.LOW))


if __name__ == "__main__":
    raise SystemExit(main())
