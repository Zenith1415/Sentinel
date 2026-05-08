"""
Phase 8 — FastAPI + SSE tests.

Tests:
  1. POST /heal returns pipeline_id
  2. GET /pipeline/{id} returns valid HealingState
  3. SSE stream emits node events as pipeline completes
  4. Force rollback requires 2 distinct approvers
  5. Single approver force-rollback is rejected
"""
import asyncio
import json
import time
import uuid

import httpx
import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Mock graph that completes immediately
# ---------------------------------------------------------------------------

_HEALED_PATCH = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract HealedVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _initialized;
    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }
    constructor() {}
    function initialize(address o) public { require(!_initialized); _initialized=true; owner=o; }
    function withdraw(uint256 a) external {
        require(balances[msg.sender] >= a);
        balances[msg.sender] -= a;
        (bool ok,) = msg.sender.call{value: a}(""); require(ok);
    }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function setOwner(address n) external onlyOwner { owner = n; }
    function getBalance() external view returns (uint256) { return address(this).balance; }
}
"""

_CRITICAL_FINDINGS = [
    {
        "vuln_type": "Reentrancy",
        "severity": "Critical",
        "affected_function": "withdraw",
        "line_range": [1, 10],
        "confidence": 0.95,
        "fix_recommendation": "Apply CEI",
        "evidence": "call before state update",
        "methodology": "static",
        "cross_contract_flag": True,
    },
]

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.test_phase7 import (
    _MockCorrelationAgent,
    _MockPatchAgent,
    _MockValidator,
    _MockDeployAgent,
    _MockMonitor,
    _make_named_agent,
)


def _fast_graph():
    from graph.healing_graph import build_healing_graph
    return build_healing_graph(
        agents=[_make_named_agent("StaticAnalysisAgent", _CRITICAL_FINDINGS)],
        correlation_agent=_MockCorrelationAgent(),
        patch_agent=_MockPatchAgent(),
        validator=_MockValidator(),
        deploy_agent=_MockDeployAgent(),
        monitor=_MockMonitor(),
    )


# ---------------------------------------------------------------------------
# Shared async client fixture
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture()
async def client():
    """AsyncClient with the FastAPI app; injects fast mock graph."""
    from api.main import app, _pipelines

    _pipelines.clear()
    app.state.graph_factory = _fast_graph

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c

    _pipelines.clear()


_VAULT_SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract VulnerableVault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 a) external {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] -= a;
    }
    function deposit() external payable { balances[msg.sender] += msg.value; }
}
"""

_HEAL_BODY = {
    "contract_source": _VAULT_SOURCE,
    "contract_address": "0x" + "1" * 40,
    "tvl_estimate": 0.0,
}


# ---------------------------------------------------------------------------
# Test 1 — POST /heal returns pipeline_id
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_post_heal_returns_pipeline_id(client):
    """POST /heal must return pipeline_id and status='started'."""
    resp = await client.post("/heal", json=_HEAL_BODY)

    assert resp.status_code == 202, f"Expected 202, got {resp.status_code}: {resp.text}"
    body = resp.json()

    assert "pipeline_id" in body, f"Response must contain pipeline_id; got {body}"
    assert body["status"] == "started", f"status must be 'started'; got {body['status']!r}"

    # pipeline_id must be a valid UUID
    try:
        uuid.UUID(body["pipeline_id"])
    except ValueError:
        pytest.fail(f"pipeline_id is not a valid UUID: {body['pipeline_id']!r}")


# ---------------------------------------------------------------------------
# Test 2 — GET /pipeline/{id} returns valid HealingState
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_pipeline_returns_healing_state(client):
    """GET /pipeline/{id} must return a dict containing all HealingState fields."""
    post = await client.post("/heal", json=_HEAL_BODY)
    pipeline_id = post.json()["pipeline_id"]

    # Wait briefly for the background task to start and store initial state
    await asyncio.sleep(0.1)

    resp = await client.get(f"/pipeline/{pipeline_id}")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    state = resp.json()
    required_keys = {
        "pipeline_id", "contract_source", "contract_address",
        "all_findings", "candidate_patches", "selected_patch",
        "gate_results", "validation_passed", "deployed", "healed", "error",
    }
    missing = required_keys - set(state.keys())
    assert not missing, f"GET /pipeline response missing keys: {missing}"

    assert state["pipeline_id"] == pipeline_id, "pipeline_id mismatch"


# ---------------------------------------------------------------------------
# Test 3 — SSE stream emits node events as pipeline completes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sse_stream_emits_node_events(client):
    """SSE stream must emit at least one 'node_complete' event per LangGraph node
    and end with a __done__ sentinel."""
    post = await client.post("/heal", json=_HEAL_BODY)
    pipeline_id = post.json()["pipeline_id"]

    await asyncio.sleep(0.05)  # let pipeline start

    events: list[dict] = []
    node_names: list[str] = []
    deadline = time.monotonic() + 15.0  # 15 s timeout

    async with client.stream("GET", f"/pipeline/{pipeline_id}/stream") as resp:
        assert resp.status_code == 200, f"SSE endpoint returned {resp.status_code}"
        async for line in resp.aiter_lines():
            if time.monotonic() > deadline:
                break
            if not line.startswith("data:"):
                continue
            raw = line[len("data:"):].strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue

            events.append(event)
            node = event.get("node", "")
            node_names.append(node)

            if node in ("__done__", "__error__", "__cancelled__", "__rollback__"):
                break

    assert len(events) > 0, "SSE stream emitted no events"

    expected_nodes = {"detect", "correlate", "patch", "validate", "deploy", "monitor"}
    seen = set(node_names)
    missing = expected_nodes - seen
    assert not missing, (
        f"SSE stream must emit events for nodes {expected_nodes}; "
        f"missing: {missing}; got: {seen}"
    )

    assert "__done__" in node_names, (
        f"SSE stream must end with __done__ sentinel; got nodes: {node_names}"
    )

    # Final event state must have healed=True
    done_event = next((e for e in events if e.get("node") == "__done__"), None)
    assert done_event is not None
    assert done_event.get("state", {}).get("healed") is True, (
        "Final SSE state must have healed=True"
    )


# ---------------------------------------------------------------------------
# Test 4 — Force rollback requires 2 distinct approvers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_force_rollback_requires_two_approvers(client):
    """POST /pipeline/{id}/force-rollback with 2 distinct approvers must succeed."""
    post = await client.post("/heal", json=_HEAL_BODY)
    pipeline_id = post.json()["pipeline_id"]

    # Give pipeline a moment to register
    await asyncio.sleep(0.1)

    resp = await client.post(
        f"/pipeline/{pipeline_id}/force-rollback",
        json={"approver_1": "alice@example.com", "approver_2": "bob@example.com"},
    )

    assert resp.status_code == 200, (
        f"Force rollback with 2 approvers must succeed; got {resp.status_code}: {resp.text}"
    )
    body = resp.json()
    assert body["pipeline_id"] == pipeline_id
    assert "rollback" in body["status"].lower(), (
        f"Response status must indicate rollback; got {body['status']!r}"
    )
    assert set(body["approvers"]) == {"alice@example.com", "bob@example.com"}


# ---------------------------------------------------------------------------
# Test 5 — Single approver force-rollback is rejected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_approver_rollback_rejected(client):
    """POST /pipeline/{id}/force-rollback with approver_1 == approver_2 must be rejected."""
    post = await client.post("/heal", json=_HEAL_BODY)
    pipeline_id = post.json()["pipeline_id"]

    await asyncio.sleep(0.1)

    # Same person listed twice
    resp = await client.post(
        f"/pipeline/{pipeline_id}/force-rollback",
        json={"approver_1": "alice@example.com", "approver_2": "alice@example.com"},
    )

    assert resp.status_code == 403, (
        f"Single approver (same person twice) must be rejected with 403; "
        f"got {resp.status_code}: {resp.text}"
    )

    # Missing second approver
    resp2 = await client.post(
        f"/pipeline/{pipeline_id}/force-rollback",
        json={"approver_1": "alice@example.com", "approver_2": ""},
    )
    assert resp2.status_code == 403, (
        f"Missing approver_2 must be rejected with 403; got {resp2.status_code}"
    )

    print("\nPHASE 8 COMPLETE — API and dashboard working")
