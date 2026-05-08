"""
Phase 1 — LangGraph state schema + Redis event bus.
Tests:
  1. HealingState has every required field
  2. publish() → subscribe() round-trip returns identical data
  3. Duplicate message with same idempotency key is NOT processed twice
  4. Failed message lands in the dead letter queue
"""
import pytest
import fakeredis

from graph.state import HealingState
from core.event_bus import (
    EventBus,
    CONTRACT_SUBMITTED,
    DETECTION_COMPLETE,
)


# ---------------------------------------------------------------------------
# Fixture — isolated in-memory bus per test
# ---------------------------------------------------------------------------

@pytest.fixture()
def bus():
    return EventBus(_client=fakeredis.FakeRedis())


# ---------------------------------------------------------------------------
# Test 1 — state schema
# ---------------------------------------------------------------------------

def test_healing_state_has_all_fields():
    required = [
        # core
        "pipeline_id", "contract_source", "contract_address",
        "solidity_version", "tvl_estimate",
        # detection
        "static_findings", "symbolic_findings", "semantic_findings",
        "governance_findings", "threat_findings", "all_findings",
        # routing
        "confidence_score", "route", "conflict_flags",
        # repair
        "candidate_patches", "selected_patch",
        # validation
        "gate_results", "validation_passed", "retry_count",
        # deploy
        "deployed", "tx_hash", "rollback_target",
        # rl
        "rl_reward", "healed", "error",
    ]
    annotations = HealingState.__annotations__
    missing = [f for f in required if f not in annotations]
    assert not missing, f"HealingState is missing fields: {missing}"


# ---------------------------------------------------------------------------
# Test 2 — publish / subscribe round-trip
# ---------------------------------------------------------------------------

def test_publish_subscribe_roundtrip(bus):
    payload = {"contract": "0xDEADBEEF", "severity": "critical", "tvl": 1_000_000}
    bus.publish(CONTRACT_SUBMITTED, "pipe-001", payload)

    results = list(bus.subscribe(CONTRACT_SUBMITTED, group="t2-group", block_ms=0))

    assert len(results) == 1
    pipeline_id, received = results[0]
    assert pipeline_id == "pipe-001"
    assert received == payload


# ---------------------------------------------------------------------------
# Test 3 — idempotency: duplicate not processed twice
# ---------------------------------------------------------------------------

def test_idempotency_prevents_duplicate_processing(bus):
    data = {"event": "submitted", "version": "1.0"}

    # Same data + same pipeline_id → same idempotency key → only one delivery
    bus.publish(CONTRACT_SUBMITTED, "pipe-002", data)
    bus.publish(CONTRACT_SUBMITTED, "pipe-002", data)

    results = list(bus.subscribe(CONTRACT_SUBMITTED, group="t3-group", block_ms=0))

    assert len(results) == 1, (
        f"Expected 1 message after deduplication, got {len(results)}"
    )


# ---------------------------------------------------------------------------
# Test 4 — failing handler sends message to DLQ
# ---------------------------------------------------------------------------

def test_failed_message_lands_in_dlq(bus):
    data = {"event": "detection", "vuln_count": 3}
    bus.publish(DETECTION_COMPLETE, "pipe-003", data)

    def failing_handler(pipeline_id: str, payload: dict) -> None:
        raise ValueError("simulated processing failure")

    bus.process(DETECTION_COMPLETE, failing_handler, group="t4-group", block_ms=0)

    dlq = bus.read_dlq()
    assert len(dlq) > 0, "Dead letter queue should contain the failed message"
    assert "ValueError" in dlq[0]["error"]
    assert dlq[0]["pipeline_id"] == "pipe-003"
    assert dlq[0]["source_topic"] == DETECTION_COMPLETE
