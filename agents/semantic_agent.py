"""
LLM semantic analysis agent — Gemini 2.0 Flash (Google free tier) for deep vulnerability reasoning.
Finds business logic flaws, economic attack vectors, and state machine violations
that static tools miss.
"""
import json
import os
import re

from langchain_core.messages import HumanMessage, SystemMessage

from core.llm import get_llm
from graph.state import HealingState

_SYSTEM = """\
You are a Solidity security expert specializing in semantic vulnerabilities.
Analyze this contract for semantic vulnerabilities that static tools miss:
- Business logic flaws (incorrect invariants, wrong state transitions)
- Economic attack vectors (price manipulation, MEV, flash loan exploits)
- State machine violations (functions callable in wrong order or phase)
- Access control logic errors (not just missing modifiers, but wrong logic)

Return a JSON array where every element has EXACTLY these keys:
{
  "vuln_type":           <string  — e.g. "Reentrancy", "FlashLoanManipulation">,
  "severity":            <"Critical"|"High"|"Medium"|"Low">,
  "affected_function":   <string  — function name>,
  "line_range":          [<start_int>, <end_int>],
  "confidence":          <float 0.0-1.0>,
  "fix_recommendation":  <string>,
  "evidence":            <string  — quote the specific code evidence>,
  "methodology":         "llm",
  "cross_contract_flag": <boolean>
}

Return ONLY the JSON array. No markdown fences, no prose."""

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


class LLMSemanticAgent:
    methodology = "llm"

    def __init__(self) -> None:
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            self._llm = get_llm(max_tokens=4096, agent_role="semantic")
        return self._llm

    def run(self, contract_source: str, state: HealingState) -> list[dict]:
        try:
            llm = self._get_llm()
        except Exception:
            return []

        raw = self._call(llm, contract_source)
        parsed = self._parse(raw)

        if parsed is None:
            # Retry once with temperature nudge (same llm, same call)
            raw = self._call(llm, contract_source)
            parsed = self._parse(raw)

        if parsed is None:
            return []

        return [self._normalize(f) for f in parsed if isinstance(f, dict)]

    def _call(self, llm, source: str) -> str:
        resp = llm.invoke([
            SystemMessage(content=_SYSTEM),
            HumanMessage(content=f"```solidity\n{source}\n```"),
        ])
        return resp.content.strip()

    def _parse(self, raw: str) -> list[dict] | None:
        clean = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
        clean = re.sub(r"\n?```$", "", clean.strip())
        try:
            data = json.loads(clean)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass
        return None

    def _normalize(self, f: dict) -> dict:
        lr = f.get("line_range", [0, 0])
        if not (isinstance(lr, (list, tuple)) and len(lr) == 2):
            lr = [0, 0]
        sev = f.get("severity", "Medium")
        return {
            "vuln_type": str(f.get("vuln_type", "Unknown")),
            "severity": sev if sev in _VALID_SEVERITIES else "Medium",
            "affected_function": str(f.get("affected_function", "unknown")),
            "line_range": [int(lr[0]), int(lr[1])],
            "confidence": max(0.0, min(1.0, float(f.get("confidence", 0.5)))),
            "fix_recommendation": str(f.get("fix_recommendation", "")),
            "evidence": str(f.get("evidence", ""))[:400],
            "methodology": self.methodology,
            "cross_contract_flag": bool(f.get("cross_contract_flag", False)),
        }
