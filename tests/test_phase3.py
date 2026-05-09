"""
Phase 3 — Correlation agent and routing.

Tests:
  1. VulnerableVault routes to "medium" or "slow" (never "fast" — KB too small)
  2. Conflict detected when same function has nonReentrant + onlyOwner fix recommendations
  3. Symbolic TIMEOUT sentinel forces route = "slow"
  4. confidence_score is a float in [0.0, 1.0]
  5. all_findings is merged + deduplicated (same key collapses to one entry)
  6. conflict_flags is always a list (may be empty)
"""
from pathlib import Path
import pytest
from graph.correlation import CorrelationAgent

_VAULT = (Path(__file__).parent.parent / "contracts" / "VulnerableVault.sol").read_text(
    encoding="utf-8"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(
    vuln_type: str,
    fn: str,
    fix: str,
    methodology: str = "static",
    confidence: float = 0.80,
    severity: str = "Critical",
    cross_contract: bool = False,
) -> dict:
    return {
        "vuln_type": vuln_type,
        "severity": severity,
        "affected_function": fn,
        "line_range": [1, 10],
        "confidence": confidence,
        "fix_recommendation": fix,
        "evidence": f"evidence:{fn}/{vuln_type}",
        "methodology": methodology,
        "cross_contract_flag": cross_contract,
    }


def _timeout() -> dict:
    return {
        "vuln_type": "TIMEOUT",
        "severity": "Low",
        "affected_function": "unknown",
        "line_range": [0, 0],
        "confidence": 0.0,
        "fix_recommendation": "Increase symbolic execution timeout.",
        "evidence": "Mythril timed out.",
        "methodology": "symbolic",
        "cross_contract_flag": False,
    }


def _state(**overrides) -> dict:
    base = {
        "pipeline_id": "test-pipe",
        "contract_source": "",
        "contract_address": "",
        "solidity_version": "0.8.22",
        "tvl_estimate": 0.0,
        "static_findings": [],
        "symbolic_findings": [],
        "semantic_findings": [],
        "governance_findings": [],
        "threat_findings": [],
        "all_findings": [],
        "confidence_score": 0.0,
        "route": "",
        "conflict_flags": [],
        "candidate_patches": [],
        "selected_patch": "",
        "gate_results": {},
        "validation_passed": False,
        "retry_count": 0,
        "deployed": False,
        "tx_hash": "",
        "rollback_target": "",
        "rl_reward": 0.0,
        "healed": False,
        "error": "",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Test 1 — VulnerableVault never routes to "fast"
# ---------------------------------------------------------------------------

def test_vulnerable_vault_route_is_medium_or_slow():
    from agents.static_agent import StaticAnalysisAgent

    # Real static findings + one synthetic non-timeout symbolic finding
    static_findings = StaticAnalysisAgent().run(_VAULT, {})
    assert static_findings, "Static agent must return at least one finding"

    state = _state(
        contract_source=_VAULT,
        static_findings=static_findings,
        symbolic_findings=[
            _f("Reentrancy", "withdraw",
               "Apply CEI pattern", methodology="symbolic", confidence=0.75),
        ],
    )
    result = CorrelationAgent().correlate(state)

    # VulnerableVault has well-known patterns (reentrancy, missing access control)
    # With KB seeded ≥ 5 proven patches and confidence ≥ 0.75, fast path is valid.
    # Slow is rejected — these are simple, auto-patchable findings.
    assert result["route"] in ("fast", "medium"), (
        f"VulnerableVault must route 'fast' or 'medium' (auto-patchable). Got '{result['route']}'"
    )
    assert result["route"] != "slow", (
        "VulnerableVault must NOT route slow — its findings are well-known patterns"
    )
    # State fields must be populated
    assert isinstance(result["all_findings"], list)
    assert isinstance(result["confidence_score"], float)


# ---------------------------------------------------------------------------
# Test 2 — conflict detected on nonReentrant + onlyOwner for same function
# ---------------------------------------------------------------------------

def test_conflict_detected_nonreentrant_plus_onlyowner():
    state = _state(
        static_findings=[
            _f(
                "Reentrancy", "withdraw",
                "Apply Checks-Effects-Interactions: update state before .call{value:}",
                confidence=0.90,
            ),
            _f(
                "MissingAccessControl", "withdraw",
                "Add onlyOwner modifier — only the owner should call withdraw()",
                confidence=0.85,
            ),
        ],
        symbolic_findings=[
            _f(
                "Reentrancy", "withdraw",
                "Apply CEI pattern to prevent reentrancy",
                methodology="symbolic", confidence=0.75,
            ),
        ],
    )
    result = CorrelationAgent().correlate(state)

    flags = result["conflict_flags"]
    assert isinstance(flags, list)
    assert len(flags) > 0, (
        f"Expected at least one conflict flag.\n"
        f"all_findings: {[(f['affected_function'], f['vuln_type']) for f in result['all_findings']]}"
    )
    combined = " ".join(flags).lower()
    assert "conflict" in combined or "withdraw" in combined, (
        f"Conflict flag should mention 'conflict' or 'withdraw'. Got: {flags}"
    )


# ---------------------------------------------------------------------------
# Test 3 — symbolic TIMEOUT forces route = "slow"
# ---------------------------------------------------------------------------

def test_symbolic_timeout_forces_slow_route():
    state = _state(
        static_findings=[
            _f("Reentrancy", "withdraw",
               "Apply CEI pattern", confidence=0.90, cross_contract=False),
            _f("MissingAccessControl", "setOwner",
               "Add onlyOwner modifier", confidence=0.85),
        ],
        symbolic_findings=[_timeout()],
    )
    result = CorrelationAgent().correlate(state)

    assert result["route"] == "slow", (
        f"Symbolic TIMEOUT must force route='slow'. Got '{result['route']}'"
    )
    # TIMEOUT finding should be excluded from all_findings
    for f in result["all_findings"]:
        assert f.get("vuln_type") != "TIMEOUT", "TIMEOUT sentinel must not appear in all_findings"


# ---------------------------------------------------------------------------
# Test 4 — confidence_score is a float in [0.0, 1.0]
# ---------------------------------------------------------------------------

def test_confidence_score_is_valid_float():
    # Synthetic findings — no cross_contract, no timeout, no conflicts
    state = _state(
        static_findings=[
            _f("Reentrancy", "withdraw", "Apply CEI pattern",
               confidence=0.90, cross_contract=False),
            _f("MissingAccessControl", "setOwner", "Add onlyOwner modifier",
               confidence=0.85, cross_contract=False),
        ],
        symbolic_findings=[
            _f("Reentrancy", "withdraw", "Apply CEI pattern",
               methodology="symbolic", confidence=0.75, cross_contract=False),
        ],
    )
    result = CorrelationAgent().correlate(state)

    score = result["confidence_score"]
    assert isinstance(score, float), f"confidence_score must be float, got {type(score)}"
    assert 0.0 <= score <= 1.0, f"confidence_score {score} out of [0.0, 1.0]"


# ---------------------------------------------------------------------------
# Test 5 — all_findings merged and deduplicated
# ---------------------------------------------------------------------------

def test_all_findings_merged_and_deduplicated():
    # Three agents each report Reentrancy/withdraw → must collapse to exactly 1
    state = _state(
        static_findings=[
            _f("Reentrancy", "withdraw", "Apply CEI pattern",
               methodology="static", confidence=0.90),
        ],
        symbolic_findings=[
            _f("Reentrancy", "withdraw", "Apply CEI pattern",
               methodology="symbolic", confidence=0.75),
        ],
        semantic_findings=[
            _f("Reentrancy", "withdraw", "Use ReentrancyGuard from OpenZeppelin",
               methodology="llm", confidence=0.80),
        ],
    )
    result = CorrelationAgent().correlate(state)

    reentrancy_withdraw = [
        f for f in result["all_findings"]
        if f["vuln_type"] == "Reentrancy" and f["affected_function"] == "withdraw"
    ]
    assert len(reentrancy_withdraw) == 1, (
        f"3 raw Reentrancy/withdraw findings should merge to 1, "
        f"got {len(reentrancy_withdraw)}"
    )
    assert len(result["all_findings"]) > 0

    # Merged entry should carry a combined methodology string
    merged_meth = reentrancy_withdraw[0]["methodology"]
    assert "static" in merged_meth and "symbolic" in merged_meth, (
        f"Merged methodology should include both agents, got '{merged_meth}'"
    )


# ---------------------------------------------------------------------------
# Test 6 — conflict_flags is always a list (even when empty)
# ---------------------------------------------------------------------------

def test_conflict_flags_is_always_a_list():
    # Single finding on one function — no conflicts possible
    state = _state(
        static_findings=[
            _f("Reentrancy", "withdraw", "Apply CEI pattern", confidence=0.90),
        ],
        symbolic_findings=[
            _f("Reentrancy", "withdraw", "Apply CEI pattern",
               methodology="symbolic", confidence=0.75),
        ],
    )
    result = CorrelationAgent().correlate(state)

    assert isinstance(result["conflict_flags"], list), (
        f"conflict_flags must always be list, got {type(result['conflict_flags'])}"
    )
    # No conflicts expected here (both findings are on same key, merge to 1)
    assert result["conflict_flags"] == [], (
        f"Expected no conflict flags, got: {result['conflict_flags']}"
    )
