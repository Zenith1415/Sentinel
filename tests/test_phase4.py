"""
Phase 4 — Master Patch Agent.

Tests:
  1. generate() returns HealingState with candidate_patches list
  2. Each candidate has required schema keys
  3. flagged_for_review=True when source diff > 40%
  4. flagged_for_review=True when Slither detects new High/Critical vuln
  5. Rejected patches (new vulns) are stored in ChromaDB rejected_patches
  6. All 3 candidates generated in parallel (asyncio.gather)
"""
import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_VAULT = (Path(__file__).parent.parent / "contracts" / "VulnerableVault.sol").read_text(
    encoding="utf-8"
)

_CANDIDATE_KEYS = {
    "id", "strategy", "patch_source", "explanation",
    "vuln_types_addressed", "flagged_for_review", "flag_reasons", "new_vulns",
}


def _state(**overrides) -> dict:
    base = {
        "pipeline_id": "test-phase4",
        "contract_source": _VAULT,
        "contract_address": "",
        "solidity_version": "0.8.22",
        "tvl_estimate": 0.0,
        "static_findings": [],
        "symbolic_findings": [],
        "semantic_findings": [],
        "governance_findings": [],
        "threat_findings": [],
        "all_findings": [
            {
                "vuln_type": "Reentrancy",
                "severity": "Critical",
                "affected_function": "withdraw",
                "line_range": [1, 10],
                "confidence": 0.90,
                "fix_recommendation": "Apply CEI pattern",
                "evidence": "withdraw calls .call{value:} before state update",
                "methodology": "static",
                "cross_contract_flag": True,
            }
        ],
        "confidence_score": 0.85,
        "route": "medium",
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


def _make_llm_response(patch_source: str = "contract Fixed {}") -> MagicMock:
    payload = json.dumps({
        "patch_source": patch_source,
        "explanation": "Fixed reentrancy with CEI pattern.",
        "vuln_types_addressed": ["Reentrancy"],
    })
    mock_resp = MagicMock()
    mock_resp.content = payload
    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(return_value=mock_resp)
    return mock_llm


# ---------------------------------------------------------------------------
# Test 1 — generate() returns state with candidate_patches list
# ---------------------------------------------------------------------------

def test_generate_returns_state_with_candidates(tmp_path):
    from agents.patch_agent import MasterPatchAgent

    agent = MasterPatchAgent(chroma_path=str(tmp_path))
    agent._llm = _make_llm_response()

    result = agent.generate(_state())

    assert "candidate_patches" in result
    assert isinstance(result["candidate_patches"], list)
    assert len(result["candidate_patches"]) > 0, "Must produce at least one candidate"


# ---------------------------------------------------------------------------
# Test 2 — each candidate has required schema keys
# ---------------------------------------------------------------------------

def test_candidate_schema_keys(tmp_path):
    from agents.patch_agent import MasterPatchAgent

    agent = MasterPatchAgent(chroma_path=str(tmp_path))
    agent._llm = _make_llm_response()

    result = agent.generate(_state())

    for c in result["candidate_patches"]:
        missing = _CANDIDATE_KEYS - set(c.keys())
        assert not missing, f"Candidate missing keys: {missing}\nCandidate: {c}"
        assert isinstance(c["flagged_for_review"], bool)
        assert isinstance(c["flag_reasons"], list)
        assert isinstance(c["new_vulns"], list)
        assert isinstance(c["vuln_types_addressed"], list)
        assert c["strategy"] in ("proven", "experimental", "pure_llm")


# ---------------------------------------------------------------------------
# Test 3 — flagged_for_review=True when source diff > 40%
# ---------------------------------------------------------------------------

def test_large_diff_flags_for_review(tmp_path):
    from agents.patch_agent import MasterPatchAgent

    agent = MasterPatchAgent(chroma_path=str(tmp_path))

    # Patch source that is completely different from original
    completely_different = "pragma solidity ^0.8.22;\n" + "\n".join(
        f"// line {i}" for i in range(200)
    )
    agent._llm = _make_llm_response(patch_source=completely_different)

    result = agent.generate(_state())

    flagged = [c for c in result["candidate_patches"] if c["flagged_for_review"]]
    assert len(flagged) > 0, (
        "At least one candidate should be flagged when diff > 40%"
    )
    for c in flagged:
        assert any("large_diff" in r for r in c["flag_reasons"]), (
            f"flag_reasons should mention large_diff, got: {c['flag_reasons']}"
        )


# ---------------------------------------------------------------------------
# Test 4 — flagged_for_review=True when Slither finds new High/Critical
# ---------------------------------------------------------------------------

def test_slither_new_vuln_flags_for_review(tmp_path):
    from agents.patch_agent import MasterPatchAgent

    agent = MasterPatchAgent(chroma_path=str(tmp_path))
    agent._llm = _make_llm_response()

    # Inject a mock _slither_new_vulns that always reports a new vuln
    agent._slither_new_vulns = lambda source, orig: ["suicidal"]

    result = agent.generate(_state())

    flagged = [c for c in result["candidate_patches"] if c["new_vulns"]]
    assert len(flagged) > 0, (
        "Candidates with new Slither vulns should be flagged"
    )
    for c in flagged:
        assert "suicidal" in c["new_vulns"]
        assert c["flagged_for_review"] is True
        assert any("new_vulns" in r for r in c["flag_reasons"])


# ---------------------------------------------------------------------------
# Test 5 — rejected patches stored in ChromaDB
# ---------------------------------------------------------------------------

def test_rejected_patches_stored_in_chroma(tmp_path):
    from agents.patch_agent import MasterPatchAgent
    import chromadb

    agent = MasterPatchAgent(chroma_path=str(tmp_path))
    agent._llm = _make_llm_response()
    agent._slither_new_vulns = lambda source, orig: ["suicidal"]

    agent.generate(_state())

    client = chromadb.PersistentClient(path=str(tmp_path))
    col = client.get_or_create_collection("rejected_patches")
    assert col.count() > 0, (
        "Rejected patches (with new vulns) must be stored in ChromaDB"
    )
    data = col.get()
    metas = data.get("metadatas", [])
    assert any("suicidal" in (m.get("new_vulns") or "") for m in metas), (
        "Stored rejected patch metadata must contain the new vuln name"
    )


# ---------------------------------------------------------------------------
# Test 6 — all 3 candidates generated in parallel
# ---------------------------------------------------------------------------

def test_three_candidates_generated_in_parallel(tmp_path):
    from agents.patch_agent import MasterPatchAgent

    DELAY = 0.06  # seconds per LLM call

    agent = MasterPatchAgent(chroma_path=str(tmp_path))

    # Slow async mock — each invocation takes DELAY seconds
    async def slow_call(messages):
        await asyncio.sleep(DELAY)
        return json.dumps({
            "patch_source": _VAULT,
            "explanation": "parallel test patch",
            "vuln_types_addressed": ["Reentrancy"],
        })

    agent._call_llm = slow_call

    t0 = time.monotonic()
    result = agent.generate(_state())
    elapsed = time.monotonic() - t0

    # If sequential: 3 × DELAY = 0.18 s. Parallel must finish in < DELAY × 2.5
    assert elapsed < DELAY * 2.5, (
        f"Expected parallel execution < {DELAY * 2.5:.3f}s, got {elapsed:.3f}s"
    )
    assert len(result["candidate_patches"]) == 3, (
        f"Expected 3 candidates from parallel generation, got {len(result['candidate_patches'])}"
    )
