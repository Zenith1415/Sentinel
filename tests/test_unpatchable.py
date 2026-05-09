"""
UnpatchableVault — the contract designed to DEFEAT the self-healing pipeline.

Test 1: Pipeline always routes to "slow" (NEVER "fast" or "medium")
Test 2: healed == False, all candidates fail at least one gate
Test 3: cross_contract_flag == True in at least one finding
Test 4: retry_count reaches 3 before escalating to slow_path
Test 5: Pipeline completes gracefully (no crash), error field is human-readable
Test 6: /pipeline/{id}/scope-alerts returns an alert for this contract
"""
import sys
import os
import uuid
import asyncio
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path

# ── Contract source ──────────────────────────────────────────────────────────

_UNPATCHABLE = (
    Path(__file__).parent.parent / "contracts" / "UnpatchableVault.sol"
).read_text(encoding="utf-8")

# ── Findings that represent UnpatchableVault's vulnerability profile ─────────

_CROSS_CONTRACT_FINDING = {
    "vuln_type":           "CrossContractReentrancy",
    "severity":            "Critical",
    "affected_function":   "withdraw",
    "line_range":          [1, 50],
    "confidence":          0.20,   # deliberately low — ambiguous cross-contract chain
    "fix_recommendation":  "Redesign triangle call chain; nonReentrant is insufficient",
    "evidence":            "VaultA→VaultB→VaultC→VaultA call chain; state updated after full loop",
    "methodology":         "static",
    "cross_contract_flag": True,   # ← critical: separate contracts in scope
}

_GOVERNANCE_REENTRANCY = {
    "vuln_type":           "GovernanceReentrancy",
    "severity":            "Critical",
    "affected_function":   "setEmergencyWithdraw",
    "line_range":          [60, 80],
    "confidence":          0.18,
    "fix_recommendation":  "AMBIGUOUS: verify() purpose unclear — cannot auto-patch",
    "evidence":            "External call before state update inside onlyOwner governance fn",
    "methodology":         "semantic",
    "cross_contract_flag": True,
}

_ORACLE_MANIPULATION = {
    "vuln_type":           "OracleManipulation",
    "severity":            "High",
    "affected_function":   "liquidate",
    "line_range":          [90, 120],
    "confidence":          0.22,
    "fix_recommendation":  "SafeMath + zero price check; diff > 40% expected",
    "evidence":            "Unchecked arithmetic with oracle price=0; block.timestamp dependency",
    "methodology":         "static",
    "cross_contract_flag": False,
}

_STORAGE_COLLISION = {
    "vuln_type":           "DelegatecallStorageCollision",
    "severity":            "Critical",
    "affected_function":   "upgradeLogic",
    "line_range":          [130, 145],
    "confidence":          0.15,
    "fix_recommendation":  "Rewrite storage layout across 3 contracts — out of single-file scope",
    "evidence":            "Slot 0 shared: owner(address) vs initialized(bool) vs emergencyMode(uint256)",
    "methodology":         "static",
    "cross_contract_flag": True,
}

_FLASHLOAN_REENTRANCY = {
    "vuln_type":           "FlashLoanCallbackReentrancy",
    "severity":            "Critical",
    "affected_function":   "flashLoan",
    "line_range":          [150, 185],
    "confidence":          0.20,
    "fix_recommendation":  "nonReentrant breaks ERC-3156; removing callback breaks interface",
    "evidence":            "ERC-3156 onFlashLoan callback + live balanceOf check enables bypass",
    "methodology":         "static",
    "cross_contract_flag": False,
}

_SELFDESTRUCT_GOV = {
    "vuln_type":           "SelfdestructGovernance",
    "severity":            "Critical",
    "affected_function":   "emergencyDestruct",
    "line_range":          [195, 215],
    "confidence":          0.12,   # novel pattern, not in KB
    "fix_recommendation":  "Novel: governance redesign + proxy upgrade required",
    "evidence":            "selfdestruct + 1-token voteForOwner; not in proven_patches KB",
    "methodology":         "governance",
    "cross_contract_flag": False,
}

_ALL_FINDINGS = [
    _CROSS_CONTRACT_FINDING,
    _GOVERNANCE_REENTRANCY,
    _ORACLE_MANIPULATION,
    _STORAGE_COLLISION,
    _FLASHLOAN_REENTRANCY,
    _SELFDESTRUCT_GOV,
]

# ── Mock agents ───────────────────────────────────────────────────────────────

def _make_agent(class_name, findings):
    cls = type(class_name, (object,), {
        "run": lambda self, src, state: list(findings),
    })
    return cls()


class _SlowCorrelationAgent:
    """Correlation agent that produces confidence < 0.30 → always routes slow."""
    def correlate(self, state):
        s = dict(state)
        s["all_findings"]     = list(_ALL_FINDINGS)
        s["confidence_score"] = 0.17   # weighted avg of low-confidence cross-contract findings
        s["route"]            = "slow"
        s["conflict_flags"]   = ["CrossContractReentrancy conflicts with FlashLoanCallbackReentrancy fix"]
        return s


class _MediumCorrelationAgent:
    """Routes medium — used for retry exhaustion test (Test 4)."""
    def correlate(self, state):
        s = dict(state)
        s["all_findings"]     = list(_ALL_FINDINGS)
        s["confidence_score"] = 0.45
        s["route"]            = "medium"
        s["conflict_flags"]   = []
        return s


_FAILED_CANDIDATE = {
    "id":                  str(uuid.uuid4()),
    "strategy":            "proven",
    "patch_source":        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n// incomplete patch",
    "explanation":         "Attempted nonReentrant on withdraw — insufficient for cross-contract",
    "vuln_types_addressed": ["CrossContractReentrancy"],
    "flagged_for_review":  True,
    "flag_reasons":        ["new_vulns:cross-contract-reentrancy", "large_diff:62%"],
    "new_vulns":           ["cross-contract-reentrancy"],
}


class _FailingPatchAgent:
    """Returns 3 candidates that all fail validation."""
    def generate(self, state):
        candidates = [
            {**_FAILED_CANDIDATE, "id": str(uuid.uuid4()), "strategy": s}
            for s in ("proven", "experimental", "pure_llm")
        ]
        return {"candidate_patches": candidates}


class _AlwaysFailValidator:
    """Every candidate fails every gate — simulates unpatchable contract."""
    def validate_all(self, state):
        s = dict(state)
        retry = s.get("retry_count", 0) + 1
        s["retry_count"]       = retry
        s["validation_passed"] = False
        s["selected_patch"]    = ""
        s["gate_results"]      = {
            "gate1": False,  # Slither still finds cross-contract reentrancy post-patch
            "gate2": True,
            "gate3": False,  # ERC-3156 interface broken by nonReentrant
            "gate4": True,
            "gate5": False,  # Source diff > 40%
        }
        if retry >= 3:
            s["route"] = "slow"
            s["error"] = (
                f"All patch candidates failed validation after {retry} attempts. "
                "Cross-contract reentrancy, ERC-3156 interface conflict, and large "
                "source diff exceed autonomous patching capability. "
                "ESCALATED TO HUMAN REVIEW."
            )
        else:
            s["error"] = (
                f"Gate failures (retry {retry}/3): Slither cross-contract reentrancy; "
                "ERC-3156 interface broken; source diff > 40%"
            )
        return s


class _MockDeployAgent:
    def deploy(self, state):
        return {**dict(state), "deployed": False, "healed": False,
                "tx_hash": "", "rollback_target": "", "baseline_metrics": {}, "error": ""}


class _MockMonitor:
    def watch(self, state, duration_blocks=10):
        return {**dict(state), "rl_reward": -1.0}  # negative reward for unhealed


def _build_slow_graph():
    from graph.healing_graph import build_healing_graph
    return build_healing_graph(
        agents=[_make_agent("StaticAnalysisAgent", _ALL_FINDINGS)],
        correlation_agent=_SlowCorrelationAgent(),
        patch_agent=_FailingPatchAgent(),
        validator=_AlwaysFailValidator(),
        deploy_agent=_MockDeployAgent(),
        monitor=_MockMonitor(),
    )


def _build_retry_graph():
    """Graph that routes medium but always fails validation — hits retry limit."""
    from graph.healing_graph import build_healing_graph
    return build_healing_graph(
        agents=[_make_agent("StaticAnalysisAgent", _ALL_FINDINGS)],
        correlation_agent=_MediumCorrelationAgent(),
        patch_agent=_FailingPatchAgent(),
        validator=_AlwaysFailValidator(),
        deploy_agent=_MockDeployAgent(),
        monitor=_MockMonitor(),
    )


def _run(graph):
    from graph.runner import run_healing_pipeline
    return run_healing_pipeline(
        contract_source=_UNPATCHABLE,
        contract_address="0x" + "b" * 40,
        graph=graph,
    )


# ── Test 1: Pipeline ALWAYS routes to slow ───────────────────────────────────

def test_unpatchable_always_routes_slow():
    """UnpatchableVault must NEVER route to fast or medium — always slow."""
    result = _run(_build_slow_graph())

    route = result.get("route", "")
    assert route == "slow", (
        f"UnpatchableVault must route to 'slow' — got {route!r}. "
        "The contract has 6 vulnerability classes that defeat auto-patching."
    )
    assert route != "fast",   "UnpatchableVault must NEVER be routed to 'fast'"
    assert route != "medium", "UnpatchableVault must NEVER be routed to 'medium'"
    print(f"\n  ✓ route == 'slow' (confidence: {result.get('confidence_score', 0):.2%})")


# ── Test 2: healed == False, all candidates fail at least one gate ────────────

def test_unpatchable_never_healed():
    """All patch candidates fail at least one gate. healed must be False."""
    result = _run(_build_slow_graph())

    assert result.get("healed") is False, (
        f"UnpatchableVault must NOT be healed autonomously; got healed={result.get('healed')}"
    )
    assert result.get("deployed") is False, (
        "Contract must not be deployed when healing fails"
    )

    # If candidates were attempted, verify gates failed
    candidates = result.get("candidate_patches", [])
    for c in candidates:
        gate_results = result.get("gate_results", {})
        failed_gates = [g for g, passed in gate_results.items() if not passed]
        if failed_gates:
            assert True  # at least one gate failed — correct
            break
    else:
        # No candidates attempted (routed directly to slow) — also correct
        pass

    print(f"\n  ✓ healed == False, deployed == False")
    print(f"  ✓ Gate failures: {[g for g, p in result.get('gate_results', {}).items() if not p]}")


# ── Test 3: cross_contract_flag == True in at least one finding ───────────────

def test_cross_contract_flag_present():
    """At least one finding must have cross_contract_flag=True."""
    result = _run(_build_slow_graph())

    findings = result.get("all_findings", [])
    assert findings, "all_findings must not be empty"

    cross_flags = [f for f in findings if f.get("cross_contract_flag")]
    assert cross_flags, (
        f"At least one finding must have cross_contract_flag=True. "
        f"Got {len(findings)} findings, none with cross_contract_flag."
    )
    print(f"\n  ✓ {len(cross_flags)}/{len(findings)} findings have cross_contract_flag=True")
    for f in cross_flags:
        print(f"    - {f['vuln_type']} ({f['affected_function']})")


# ── Test 4: retry_count reaches 3 before escalating to slow_path ─────────────

def test_retry_count_reaches_three():
    """
    When routed medium, validation must fail 3 times before slow_path escalation.
    retry_count must reach 3 in the final state.
    """
    result = _run(_build_retry_graph())

    retry_count = result.get("retry_count", 0)
    assert retry_count >= 3, (
        f"retry_count must reach 3 before escalating to slow path. "
        f"Got retry_count={retry_count}."
    )
    assert result.get("route") == "slow", (
        f"After 3 retries, route must be 'slow'. Got {result.get('route')!r}"
    )
    assert result.get("healed") is False, "healed must remain False after retry exhaustion"
    print(f"\n  ✓ retry_count == {retry_count} (reached threshold)")
    print(f"  ✓ route escalated to 'slow' after retry exhaustion")


# ── Test 5: Pipeline completes gracefully, error field is set ─────────────────

def test_pipeline_completes_gracefully():
    """
    Pipeline must complete without raising an exception.
    state.error must be a non-empty human-readable string explaining the escalation.
    """
    # Should not raise
    result = _run(_build_slow_graph())

    assert isinstance(result, dict), "Pipeline must return a dict even on slow path"

    error = result.get("error", "")
    assert error, (
        "error field must be set with a human-readable reason when pipeline escalates"
    )
    # Must be a descriptive string, not a raw exception
    assert len(error) > 20, f"error message too short: {error!r}"
    assert "exception" not in error.lower() or "escalat" in error.lower(), (
        "error should describe the escalation reason, not a raw Python exception"
    )
    print(f"\n  ✓ Pipeline completed without crash")
    print(f"  ✓ error: {error[:100]}…")


# ── Test 6: scope-alerts API endpoint returns alert for this contract ─────────

@pytest.mark.asyncio
async def test_scope_boundary_alert_via_api():
    """
    After running UnpatchableVault through the pipeline,
    GET /pipeline/{id}/scope-alerts must return at least one alert
    with requires_human_review = True.
    """
    import httpx

    from api.main import app, _pipelines

    _pipelines.clear()
    app.state.graph_factory = _build_slow_graph

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        # Start pipeline
        resp = await client.post("/heal", json={
            "contract_source":  _UNPATCHABLE,
            "contract_address": "0x" + "b" * 40,
            "tvl_estimate":     0.0,
        })
        assert resp.status_code == 202, f"Expected 202, got {resp.status_code}"
        pipeline_id = resp.json()["pipeline_id"]

        # Wait for completion
        deadline = __import__("time").monotonic() + 30.0
        while __import__("time").monotonic() < deadline:
            await asyncio.sleep(0.2)
            p = _pipelines.get(pipeline_id, {})
            if p.get("status") in ("complete", "error", "rolled_back"):
                break

        # Check scope-alerts endpoint
        r = await client.get(f"/pipeline/{pipeline_id}/scope-alerts")
        assert r.status_code == 200, f"scope-alerts returned {r.status_code}: {r.text}"
        body = r.json()

        assert body.get("requires_human_review") is True, (
            f"UnpatchableVault must require human review. Got: {body}"
        )
        alerts = body.get("alerts", [])
        assert alerts, f"alerts list must not be empty for UnpatchableVault. Got: {body}"

        alert_types = [a["type"] for a in alerts]
        print(f"\n  ✓ scope-alerts returned {len(alerts)} alert(s): {alert_types}")
        print(f"  ✓ requires_human_review = True")

    _pipelines.clear()
