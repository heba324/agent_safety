import json
import subprocess
import sys
from pathlib import Path

from agent_risk.config import load_env_file

ROOT = Path(__file__).resolve().parents[1]


def test_llm_check_cli_reports_missing_key_without_traceback(monkeypatch):
    monkeypatch.delenv("AGENT_RISK_LLM_API_KEY", raising=False)

    completed = subprocess.run(
        [sys.executable, "-m", "agent_risk.llm_check"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert payload["ok"] is False
    assert "AGENT_RISK_LLM_API_KEY" in payload["error"]


def test_load_env_file_sets_missing_values(tmp_path: Path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "AGENT_RISK_LLM_MODEL=Qwen/Qwen3-8B\n"
        "AGENT_RISK_LLM_BASE_URL=https://api.siliconflow.cn/v1\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("AGENT_RISK_LLM_MODEL", raising=False)

    load_env_file(env_file)

    assert __import__("os").getenv("AGENT_RISK_LLM_MODEL") == "Qwen/Qwen3-8B"
