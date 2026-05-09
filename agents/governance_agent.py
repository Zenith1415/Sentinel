"""
Governance monitoring agent — regex pattern library (primary) + Gemini 2.0 Flash for depth.
Detects: unprotected initializers, missing timelocks, upgrade path issues,
flash loan voting risk, and ownership centralisation.
"""
import json
import os
import re

from langchain_core.messages import HumanMessage, SystemMessage

from core.llm import get_llm
from graph.state import HealingState

_SYSTEM = """\
You are a smart contract governance security expert.
Analyze the contract for governance-layer vulnerabilities:
- Flash loan voting attacks (token-based quorum without snapshot)
- Missing timelocks on privileged operations (upgrade, pause, parameter changes)
- Ownership centralisation (single EOA controls critical functions)
- Unprotected emergency powers

Return a JSON array.  Every element must have EXACTLY these keys:
vuln_type, severity, affected_function, line_range (2-element int array),
confidence (float), fix_recommendation, evidence, methodology (="governance"),
cross_contract_flag (bool).
Return ONLY the JSON array."""

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}

# Each entry: regex to match a line, regex whose ABSENCE signals a finding
_PATTERNS = [
    {
        "regex": r"function\s+initialize\s*\(",
        # Accept common initializer guards: OZ `initializer`, custom `onlyInitializing`,
        # or a manual `_initialized` / `initialized` boolean guard.
        "absence": r"\binitializer\b|\bonlyInitializing\b|\b_?initialized\b",
        "vuln_type": "UnprotectedInitializer",
        "severity": "Critical",
        "confidence": 0.85,
        "fix": (
            "Add OpenZeppelin `initializer` modifier so the function "
            "can only be called once."
        ),
    },
    {
        "regex": r"function\s+setOwner\s*\(",
        "absence": r"\bonlyOwner\b",
        "vuln_type": "MissingOwnershipProtection",
        "severity": "Critical",
        "confidence": 0.90,
        "fix": "Add `onlyOwner` modifier to prevent any address from hijacking ownership.",
    },
    {
        "regex": r"function\s+(?:pause|unpause|freeze)\s*\(",
        "absence": r"\bonlyOwner\b|\bonlyRole\b|\bonlyAdmin\b",
        "vuln_type": "UnprotectedEmergencyPower",
        "severity": "High",
        "confidence": 0.80,
        "fix": "Guard emergency functions with a timelock or multisig.",
    },
    {
        "regex": r"function\s+(?:vote|propose|execute|queue)\s*\(",
        "absence": r"getPriorVotes|getVotes|snapshot|_getVotes",
        "vuln_type": "FlashLoanVotingRisk",
        "severity": "High",
        "confidence": 0.65,
        "fix": (
            "Use ERC20Votes with snapshot-based voting "
            "to prevent flash loan governance manipulation."
        ),
    },
]


class GovernanceMonitorAgent:
    methodology = "governance"

    def __init__(self) -> None:
        self._llm = None

    def _get_llm(self):
        if self._llm is None:
            self._llm = get_llm(max_tokens=2048, agent_role="governance")
        return self._llm

    def run(self, contract_source: str, state: HealingState) -> list[dict]:
        findings: list[dict] = []
        findings += self._pattern_findings(contract_source)
        findings += self._llm_findings(contract_source)
        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # Pattern-based (no external deps)
    # ------------------------------------------------------------------

    def _pattern_findings(self, source: str) -> list[dict]:
        lines = source.splitlines()
        findings: list[dict] = []

        for pat in _PATTERNS:
            for i, line in enumerate(lines):
                if not re.search(pat["regex"], line):
                    continue
                # Inspect the entire function signature (until the opening brace,
                # capped at 10 lines for malformed code). Multi-line signatures
                # are common — modifiers like `onlyInitializing` may live on the
                # closing line, not the opening one.
                sig_lines = []
                for j in range(max(0, i - 1), min(i + 10, len(lines))):
                    sig_lines.append(lines[j])
                    if "{" in lines[j] and j > i:
                        break
                sig_clean = re.sub(r"//[^\n]*", "", "\n".join(sig_lines))
                if re.search(pat["absence"], sig_clean):
                    continue  # protection present — no finding
                fn_m = re.search(r"function\s+(\w+)", line)
                fn = fn_m.group(1) if fn_m else "unknown"
                findings.append({
                    "vuln_type": pat["vuln_type"],
                    "severity": pat["severity"],
                    "affected_function": fn,
                    "line_range": [i + 1, min(i + 5, len(lines))],
                    "confidence": pat["confidence"],
                    "fix_recommendation": pat["fix"],
                    "evidence": f"Line {i + 1}: `{line.strip()}`",
                    "methodology": self.methodology,
                    "cross_contract_flag": False,
                })

        return findings

    # ------------------------------------------------------------------
    # LLM-based (optional — fails silently)
    # ------------------------------------------------------------------

    def _llm_findings(self, source: str) -> list[dict]:
        try:
            llm = self._get_llm()
            resp = llm.invoke([
                SystemMessage(content=_SYSTEM),
                HumanMessage(content=f"```solidity\n{source}\n```"),
            ])
            raw = resp.content.strip()
            raw = re.sub(r"^```[a-z]*\n?", "", raw, flags=re.MULTILINE)
            raw = re.sub(r"\n?```$", "", raw.strip())
            data = json.loads(raw)
            if not isinstance(data, list):
                return []
            return [self._normalize(f) for f in data if isinstance(f, dict)]
        except Exception:
            return []

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

    def _deduplicate(self, findings: list[dict]) -> list[dict]:
        seen: set[tuple] = set()
        out = []
        for f in findings:
            key = (f["vuln_type"], f["affected_function"])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
