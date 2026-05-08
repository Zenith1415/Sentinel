"""
Phase 2 — 5 specialist detection agents.
Tests:
  1. StaticAnalysisAgent finds reentrancy in withdraw()
  2. LLMSemanticAgent returns valid JSON finding schema (mocked LLM)
  3. SymbolicExecutionAgent returns within 95 seconds (timeout handling works)
  4. All 5 agents return list[dict] with correct schema
  5. cross_contract_flag is present (and is bool) in every finding
"""
import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

_VAULT_PATH = Path(__file__).parent.parent / "contracts" / "VulnerableVault.sol"
_VAULT = _VAULT_PATH.read_text(encoding="utf-8")

_SCHEMA_KEYS = {
    "vuln_type", "severity", "affected_function", "line_range",
    "confidence", "fix_recommendation", "evidence",
    "methodology", "cross_contract_flag",
}
_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}

STATE: dict = {}  # empty dict satisfies HealingState type in tests


def _validate_findings(findings: list[dict], agent_name: str = "") -> None:
    for f in findings:
        missing = _SCHEMA_KEYS - set(f.keys())
        assert not missing, (
            f"{agent_name}: finding missing keys {missing}\nFinding: {f}"
        )
        assert f["severity"] in _VALID_SEVERITIES, (
            f"{agent_name}: bad severity {f['severity']!r}"
        )
        lr = f["line_range"]
        assert isinstance(lr, (list, tuple)) and len(lr) == 2, (
            f"{agent_name}: line_range must be [int,int], got {lr!r}"
        )
        conf = float(f["confidence"])
        assert 0.0 <= conf <= 1.0, (
            f"{agent_name}: confidence {conf} out of [0,1]"
        )
        assert isinstance(f["cross_contract_flag"], bool), (
            f"{agent_name}: cross_contract_flag must be bool, got {type(f['cross_contract_flag'])}"
        )


def _mock_llm(findings_list: list[dict]) -> MagicMock:
    """Return a mock ChatGoogleGenerativeAI instance whose invoke() returns findings_list as JSON."""
    mock_resp = MagicMock()
    mock_resp.content = json.dumps(findings_list)
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = mock_resp
    return mock_llm


# Pre-built valid finding for injection into LLM mocks
_SEMANTIC_FINDING = {
    "vuln_type": "Reentrancy",
    "severity": "Critical",
    "affected_function": "withdraw",
    "line_range": [40, 48],
    "confidence": 0.95,
    "fix_recommendation": "Apply Checks-Effects-Interactions: update balances before .call{value:}.",
    "evidence": "msg.sender.call{value: amount} on line 42 precedes balances[msg.sender] -= amount on line 46.",
    "methodology": "llm",
    "cross_contract_flag": True,
}

_GOVERNANCE_FINDING = {
    **_SEMANTIC_FINDING,
    "vuln_type": "MissingOwnershipProtection",
    "affected_function": "setOwner",
    "evidence": "setOwner() has no onlyOwner modifier.",
    "methodology": "governance",
    "cross_contract_flag": False,
}


# ---------------------------------------------------------------------------
# Test 1 — StaticAnalysisAgent MUST detect reentrancy
# ---------------------------------------------------------------------------

def test_static_finds_reentrancy():
    from agents.static_agent import StaticAnalysisAgent

    agent = StaticAnalysisAgent()
    findings = agent.run(_VAULT, STATE)

    assert isinstance(findings, list), "run() must return list"
    _validate_findings(findings, "StaticAnalysisAgent")

    vuln_types_lower = [f["vuln_type"].lower() for f in findings]
    assert any("reentrancy" in vt for vt in vuln_types_lower), (
        f"StaticAnalysisAgent MUST find Reentrancy.\n"
        f"Found: {[f['vuln_type'] for f in findings]}"
    )


# ---------------------------------------------------------------------------
# Test 2 — LLMSemanticAgent returns valid schema (mocked LLM)
# ---------------------------------------------------------------------------

def test_semantic_agent_valid_schema():
    from agents.semantic_agent import LLMSemanticAgent

    agent = LLMSemanticAgent()
    agent._llm = _mock_llm([_SEMANTIC_FINDING])  # inject mock, bypasses API key

    findings = agent.run(_VAULT, STATE)

    assert isinstance(findings, list)
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    _validate_findings(findings, "LLMSemanticAgent")
    assert findings[0]["methodology"] == "llm"


# ---------------------------------------------------------------------------
# Test 3 — SymbolicExecutionAgent returns within 95 seconds
# ---------------------------------------------------------------------------

def test_symbolic_agent_returns_within_timeout():
    from agents.symbolic_agent import SymbolicExecutionAgent

    agent = SymbolicExecutionAgent()
    t0 = time.monotonic()
    findings = agent.run(_VAULT, STATE)
    elapsed = time.monotonic() - t0

    assert elapsed < 95.0, (
        f"SymbolicExecutionAgent exceeded 95s budget (took {elapsed:.2f}s)"
    )
    assert isinstance(findings, list), "run() must return list"
    _validate_findings(findings, "SymbolicExecutionAgent")


# ---------------------------------------------------------------------------
# Test 4 — all 5 agents return list[dict] with correct schema
# ---------------------------------------------------------------------------

def test_all_five_agents_return_valid_schema(tmp_path):
    from agents.static_agent import StaticAnalysisAgent
    from agents.symbolic_agent import SymbolicExecutionAgent
    from agents.semantic_agent import LLMSemanticAgent
    from agents.governance_agent import GovernanceMonitorAgent
    from agents.threat_pattern_agent import ThreatPatternAgent

    sem_agent = LLMSemanticAgent()
    sem_agent._llm = _mock_llm([_SEMANTIC_FINDING])

    gov_agent = GovernanceMonitorAgent()
    gov_agent._llm = _mock_llm([_GOVERNANCE_FINDING])

    agents = [
        ("StaticAnalysisAgent",    StaticAnalysisAgent()),
        ("SymbolicExecutionAgent", SymbolicExecutionAgent()),
        ("LLMSemanticAgent",       sem_agent),
        ("GovernanceMonitorAgent", gov_agent),
        ("ThreatPatternAgent",     ThreatPatternAgent(chroma_path=str(tmp_path))),
    ]

    for name, agent in agents:
        findings = agent.run(_VAULT, STATE)
        assert isinstance(findings, list), f"{name}.run() must return list"
        _validate_findings(findings, name)


# ---------------------------------------------------------------------------
# Test 5 — cross_contract_flag is present and bool in every finding
# ---------------------------------------------------------------------------

def test_cross_contract_flag_present_in_every_finding(tmp_path):
    from agents.static_agent import StaticAnalysisAgent
    from agents.symbolic_agent import SymbolicExecutionAgent
    from agents.semantic_agent import LLMSemanticAgent
    from agents.governance_agent import GovernanceMonitorAgent
    from agents.threat_pattern_agent import ThreatPatternAgent

    sem_agent = LLMSemanticAgent()
    sem_agent._llm = _mock_llm([_SEMANTIC_FINDING])

    gov_agent = GovernanceMonitorAgent()
    gov_agent._llm = _mock_llm([_GOVERNANCE_FINDING])

    all_findings: list[dict] = []
    for agent in [
        StaticAnalysisAgent(),
        SymbolicExecutionAgent(),
        sem_agent,
        gov_agent,
        ThreatPatternAgent(chroma_path=str(tmp_path)),
    ]:
        all_findings.extend(agent.run(_VAULT, STATE))

    assert all_findings, "At least one finding expected across all agents"

    for f in all_findings:
        assert "cross_contract_flag" in f, (
            f"cross_contract_flag missing from finding: {f}"
        )
        assert isinstance(f["cross_contract_flag"], bool), (
            f"cross_contract_flag must be bool; got {type(f['cross_contract_flag'])} in {f}"
        )
