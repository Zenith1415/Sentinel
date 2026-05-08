"""
Phase 6 — Deploy Agent, Rollback Mechanism, Post-Deploy Monitor.

Tests:
  1. Baseline snapshot captures gas + call data per function
  2. Deploy succeeds (mocked Hardhat): tx_hash and rollback_target set in state
  3. HealingComplete event emitted with all required fields
  4. Rollback triggered when gas spike injected post-deploy
  5. Freeze triggered when rollback_target is also anomalous
  6. Unauthorised upgrade attempt publishes alert to event bus
"""
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Solidity fixture
# ---------------------------------------------------------------------------

_HEALED_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract HealedVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _initialized;
    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }
    constructor() {}
    function initialize(address initialOwner) public {
        require(!_initialized);
        _initialized = true;
        owner = initialOwner;
    }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function setOwner(address newOwner) external onlyOwner { owner = newOwner; }
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
    {
        "vuln_type": "MissingAccessControl",
        "severity": "Critical",
        "affected_function": "setOwner",
        "line_range": [20, 25],
        "confidence": 0.90,
        "fix_recommendation": "Add onlyOwner",
        "evidence": "no access modifier",
        "methodology": "static",
        "cross_contract_flag": False,
    },
]

_BASELINE = {
    "withdraw": {
        "avg_gas": 50_000,
        "p95_gas": 75_000,
        "call_frequency": 10.0,
        "revert_rate": 0.05,
        "typical_balance_delta": -1.0,
    },
    "deposit": {
        "avg_gas": 30_000,
        "p95_gas": 35_000,
        "call_frequency": 15.0,
        "revert_rate": 0.01,
        "typical_balance_delta": 1.0,
    },
}


def _state(**overrides) -> dict:
    base = {
        "pipeline_id": "test-phase6",
        "contract_source": _HEALED_VAULT,
        "contract_address": "0x" + "1" * 40,
        "solidity_version": "0.8.22",
        "tvl_estimate": 0.0,
        "static_findings": [],
        "symbolic_findings": [],
        "semantic_findings": [],
        "governance_findings": [],
        "threat_findings": [],
        "all_findings": list(_CRITICAL_FINDINGS),
        "confidence_score": 0.85,
        "route": "medium",
        "conflict_flags": [],
        "candidate_patches": [],
        "selected_patch": _HEALED_VAULT,
        "gate_results": {},
        "validation_passed": True,
        "retry_count": 0,
        "deployed": False,
        "tx_hash": "",
        "rollback_target": "",
        "rl_reward": 0.6,
        "healed": False,
        "error": "",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Test 1 — Baseline snapshot captures gas + call data per function
# ---------------------------------------------------------------------------

def test_baseline_snapshot_captures_gas_and_call_data(tmp_path):
    """_calculate_baseline_metrics must produce avg_gas, p95_gas,
    call_frequency, revert_rate, and typical_balance_delta per function."""
    from deploy.deployer import DeployAgent

    agent = DeployAgent(chroma_path=str(tmp_path))

    tx_history = [
        {"function": "withdraw", "gas_used": 50_000, "status": 1, "balance_delta": -1.0},
        {"function": "withdraw", "gas_used": 70_000, "status": 1, "balance_delta": -2.0},
        {"function": "withdraw", "gas_used": 90_000, "status": 0, "balance_delta": 0.0},
        {"function": "deposit",  "gas_used": 30_000, "status": 1, "balance_delta": 1.0},
        {"function": "deposit",  "gas_used": 32_000, "status": 1, "balance_delta": 0.5},
    ]

    baseline = agent._calculate_baseline_metrics(tx_history, total_blocks=1_000)

    # Both functions must be present
    assert "withdraw" in baseline, "withdraw function must appear in baseline"
    assert "deposit" in baseline,  "deposit function must appear in baseline"

    required_keys = {"avg_gas", "p95_gas", "call_frequency", "revert_rate", "typical_balance_delta"}
    for fn in ("withdraw", "deposit"):
        missing = required_keys - set(baseline[fn].keys())
        assert not missing, f"{fn}: baseline missing keys {missing}"

    w = baseline["withdraw"]
    # avg_gas for 3 withdraw txs
    assert w["avg_gas"] == pytest.approx((50_000 + 70_000 + 90_000) / 3, rel=0.01)
    # 1 of 3 reverted → revert_rate = 1/3
    assert w["revert_rate"] == pytest.approx(1 / 3, rel=0.01)
    # call_frequency: 3 calls / 1000 blocks × 1000 = 3.0
    assert w["call_frequency"] == pytest.approx(3.0, rel=0.01)
    # p95_gas: sorted [50k, 70k, 90k], idx = int(2 * 0.95) = 1 → 70 000
    assert w["p95_gas"] == 70_000

    d = baseline["deposit"]
    assert d["avg_gas"] == pytest.approx(31_000, rel=0.01)
    assert d["revert_rate"] == 0.0
    assert d["typical_balance_delta"] == pytest.approx(0.75, rel=0.01)


# ---------------------------------------------------------------------------
# Test 2 — Deploy succeeds: tx_hash and rollback_target set
# ---------------------------------------------------------------------------

def test_deploy_succeeds_tx_hash_set(tmp_path):
    """deploy() must set state.tx_hash, state.rollback_target,
    state.deployed=True, and state.healed=True when all steps succeed."""
    from deploy.deployer import DeployAgent

    IMPL_ADDR = "0x" + "b" * 40
    TX_HASH   = "0x" + "c" * 64
    PREV_IMPL = "0x" + "a" * 40

    agent = DeployAgent(chroma_path=str(tmp_path))

    # Mock every Web3-touching step
    agent._capture_baseline         = lambda s: {**s, "baseline_metrics": dict(_BASELINE)}
    agent._check_proxy_access_control = lambda s: True
    agent._get_current_implementation = lambda s: PREV_IMPL
    agent._compile_patch            = lambda src: ([], "0xdeadbeef")
    agent._deploy_implementation    = lambda abi, bc, s: IMPL_ADDR
    agent._upgrade_proxy            = lambda impl, s: TX_HASH
    agent._emit_healing_complete    = lambda s, impl, tx: None

    result = agent.deploy(_state())

    assert result["deployed"]  is True,       "deployed must be True after success"
    assert result["healed"]    is True,       "healed must be True after success"
    assert result["tx_hash"]   == TX_HASH,    "tx_hash must match upgrade transaction"
    assert result["rollback_target"] == PREV_IMPL, "rollback_target must be previous impl"
    assert result["error"]     == "",         "error must be empty on success"
    assert "baseline_metrics" in result,      "baseline_metrics must be stored in state"


# ---------------------------------------------------------------------------
# Test 3 — HealingComplete event emitted with all required fields
# ---------------------------------------------------------------------------

def test_healing_complete_event_has_all_fields(tmp_path):
    """_emit_healing_complete must call _emit_on_chain_event with a payload
    containing all required HealingComplete fields."""
    from deploy.deployer import DeployAgent

    captured_events: list[dict] = []

    agent = DeployAgent(chroma_path=str(tmp_path))
    agent._emit_on_chain_event = lambda name, data: captured_events.append(
        {"_event_name": name, **data}
    )

    state = _state(
        selected_patch=_HEALED_VAULT,
        all_findings=list(_CRITICAL_FINDINGS),
        rl_reward=0.8,
        rollback_target="0x" + "a" * 40,
    )

    agent._emit_healing_complete(state, "0x" + "b" * 40, "0x" + "c" * 64)

    assert len(captured_events) == 1, "Exactly one HealingComplete event must be emitted"
    event = captured_events[0]

    assert event["_event_name"] == "HealingComplete"

    required = {"vulns_fixed", "patch_hash", "merkle_root_of_source",
                "rl_confidence", "rollback_available"}
    missing = required - set(event.keys())
    assert not missing, f"HealingComplete missing fields: {missing}"

    assert isinstance(event["vulns_fixed"], list),   "vulns_fixed must be a list"
    assert len(event["vulns_fixed"]) > 0,            "vulns_fixed must not be empty"
    assert any(v in event["vulns_fixed"] for v in ("Reentrancy", "MissingAccessControl"))

    assert event["patch_hash"].startswith("0x"),          "patch_hash must be hex"
    assert event["merkle_root_of_source"].startswith("0x"), "merkle_root must be hex"
    assert isinstance(event["rl_confidence"], float),     "rl_confidence must be float"
    assert event["rollback_available"] is True,           "rollback_available must be True"


# ---------------------------------------------------------------------------
# Test 4 — Rollback triggered when gas spike injected
# ---------------------------------------------------------------------------

def test_rollback_triggered_on_gas_spike(tmp_path):
    """When a monitored block shows avg_gas > p95_gas * 1.5, PostDeployMonitor
    must call _perform_rollback (not _freeze_contract)."""
    from core.monitor import PostDeployMonitor

    rollback_calls: list[list] = []
    freeze_calls:   list[list] = []

    monitor = PostDeployMonitor()
    monitor._poll_interval = 0  # no sleeping in tests

    # One block: block 1001 shows a gas spike on 'withdraw'
    monitor._get_start_block      = lambda: 1000
    monitor._block_range          = lambda start, end: iter([1001])
    monitor._collect_metrics_at_block = lambda blk, s: {
        "withdraw": {"avg_gas": 200_000, "revert_rate": 0.05}
        # 200 000 > 75 000 * 1.5 = 112 500  ← gas spike
    }
    monitor._is_rollback_target_anomalous = lambda target, s: False
    monitor._perform_rollback     = lambda s, anomalies: rollback_calls.append(anomalies)
    monitor._freeze_contract      = lambda s, anomalies: freeze_calls.append(anomalies)

    state = _state(
        rollback_target="0x" + "a" * 40,
        baseline_metrics=dict(_BASELINE),
    )

    monitor.watch(state, duration_blocks=1)

    assert len(rollback_calls) == 1, "Rollback must be triggered exactly once on gas spike"
    assert len(freeze_calls)   == 0, "Freeze must NOT be triggered when rollback target is clean"
    anomaly_types = {a["type"] for a in rollback_calls[0]}
    assert "gas_spike" in anomaly_types, f"gas_spike must be in anomaly types; got {anomaly_types}"


# ---------------------------------------------------------------------------
# Test 5 — Freeze triggered when rollback_target is also anomalous
# ---------------------------------------------------------------------------

def test_freeze_triggered_when_rollback_target_anomalous(tmp_path):
    """When both the current impl and the rollback_target are anomalous,
    PostDeployMonitor must activate the circuit breaker (freeze), not rollback."""
    from core.monitor import PostDeployMonitor

    rollback_calls: list = []
    freeze_calls:   list[list] = []

    monitor = PostDeployMonitor()
    monitor._poll_interval = 0
    monitor._get_start_block      = lambda: 1000
    monitor._block_range          = lambda start, end: iter([1001])
    monitor._collect_metrics_at_block = lambda blk, s: {
        "withdraw": {"avg_gas": 200_000, "revert_rate": 0.05}
    }
    monitor._is_rollback_target_anomalous = lambda target, s: True   # BOTH compromised
    monitor._perform_rollback     = lambda s, anomalies: rollback_calls.append(anomalies)
    monitor._freeze_contract      = lambda s, anomalies: freeze_calls.append(anomalies)

    state = _state(
        rollback_target="0x" + "a" * 40,
        rollback_target_anomalous=True,
        baseline_metrics=dict(_BASELINE),
    )

    monitor.watch(state, duration_blocks=1)

    assert len(freeze_calls) == 1,   "Circuit breaker must be activated once"
    assert len(rollback_calls) == 0, "Rollback must NOT be called when target is anomalous"
    anomaly_types = {a["type"] for a in freeze_calls[0]}
    assert "gas_spike" in anomaly_types, f"gas_spike anomaly expected; got {anomaly_types}"


# ---------------------------------------------------------------------------
# Test 6 — Unauthorised upgrade attempt publishes alert to event bus
# ---------------------------------------------------------------------------

def test_unauthorised_upgrade_publishes_event_bus_alert(tmp_path):
    """When _check_proxy_access_control returns False, deploy() must:
      • publish to 'unauthorised.upgrade.detected' stream on the event bus
      • set state.route = 'slow'
      • set state.deployed = False
    """
    import fakeredis
    from core.event_bus import EventBus
    from deploy.deployer import UNAUTHORISED_UPGRADE_TOPIC, DeployAgent

    fake_redis = fakeredis.FakeRedis()
    bus = EventBus(_client=fake_redis)

    agent = DeployAgent(
        chroma_path=str(tmp_path),
        event_bus=bus,
        multisig_address="0x" + "a" * 40,
    )

    # Force access-control check to fail (wrong upgrader)
    agent._capture_baseline           = lambda s: {**s, "baseline_metrics": {}}
    agent._check_proxy_access_control = lambda s: False

    result = agent.deploy(_state(contract_address="0x" + "2" * 40))

    # State assertions
    assert result["deployed"] is False, "deployed must be False on unauthorized attempt"
    assert result["route"] == "slow",   "route must be forced to 'slow'"
    assert result["error"],             "error must be non-empty"

    # Event bus assertions — the stream must contain the alert
    raw = fake_redis.xread({UNAUTHORISED_UPGRADE_TOPIC: "0"})
    assert raw, (
        f"Event bus stream '{UNAUTHORISED_UPGRADE_TOPIC}' must contain the alert. "
        f"Stream was empty."
    )
    # Decode the payload
    import json
    _, entries = raw[0]
    _, fields = entries[0]
    payload = json.loads(
        fields.get(b"payload", fields.get("payload", b"{}"))
    )
    assert "proxy_address" in payload, "Alert payload must contain proxy_address"
    assert "expected_upgrader" in payload, "Alert payload must contain expected_upgrader"
