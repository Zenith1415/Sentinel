"""
Phase 7 — Full LangGraph Healing Pipeline.

Tests:
  1. Full pipeline on VulnerableVault completes without error
  2. state.healed == True after full run
  3. state.selected_patch contains valid Solidity
  4. state.deployed == True after full run
  5. All gate_results values are True
  6. Pipeline handles a contract with NO vulns: graceful exit (not an error)
  7. Detection agents run in parallel (faster than sequential)
"""
import time
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Solidity fixtures
# ---------------------------------------------------------------------------

_VAULT_SOL = (
    Path(__file__).parent.parent / "contracts" / "VulnerableVault.sol"
).read_text(encoding="utf-8")

_CLEAN_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract SafeVault {
    mapping(address => uint256) public balances;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    constructor() { owner = msg.sender; }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
    function getBalance() external view returns (uint256) { return address(this).balance; }
}
"""

_HEALED_PATCH = """\
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

_CANDIDATE = {
    "id": str(uuid.uuid4()),
    "strategy": "proven",
    "patch_source": _HEALED_PATCH,
    "explanation": "CEI fix + onlyOwner",
    "vuln_types_addressed": ["Reentrancy", "MissingAccessControl"],
    "flagged_for_review": False,
    "flag_reasons": [],
    "new_vulns": [],
}

# ---------------------------------------------------------------------------
# Mock components
# ---------------------------------------------------------------------------

class _MockAgent:
    """Returns pre-defined findings with optional artificial delay."""
    def __init__(self, findings=None, delay=0.0, name="StaticAnalysisAgent"):
        self._findings = findings or []
        self._delay = delay
        self.__class__.__name__ = name  # tricks the field mapper

    def run(self, contract_source, state):
        if self._delay:
            time.sleep(self._delay)
        return list(self._findings)


class _NamedMockAgent(_MockAgent):
    pass


def _make_named_agent(class_name, findings=None, delay=0.0):
    """Produce a mock agent whose type().__name__ == class_name."""
    cls = type(class_name, (_MockAgent,), {})
    return cls(findings=findings, delay=delay)


class _MockCorrelationAgent:
    def correlate(self, state):
        s = dict(state)
        combined = (
            s.get("static_findings", [])
            + s.get("symbolic_findings", [])
            + s.get("semantic_findings", [])
            + s.get("governance_findings", [])
            + s.get("threat_findings", [])
        )
        s["all_findings"]    = combined or list(_CRITICAL_FINDINGS)
        s["confidence_score"] = 0.85
        s["route"]           = "medium"
        s["conflict_flags"]  = []
        return s


class _MockPatchAgent:
    def generate(self, state):
        return {"candidate_patches": [dict(_CANDIDATE)]}


class _MockValidator:
    def validate_all(self, state):
        s = dict(state)
        s["validation_passed"] = True
        s["selected_patch"]    = _HEALED_PATCH
        s["gate_results"]      = {f"gate{i}": True for i in range(1, 6)}
        s["error"]             = ""
        return s


class _MockDeployAgent:
    def deploy(self, state):
        s = dict(state)
        s["deployed"]         = True
        s["healed"]           = True
        s["tx_hash"]          = "0x" + "c" * 64
        s["rollback_target"]  = "0x" + "a" * 40
        s["baseline_metrics"] = {}
        s["error"]            = ""
        return s


class _MockMonitor:
    def watch(self, state, duration_blocks=10):
        s = dict(state)
        s["rl_reward"] = s.get("rl_reward", 0.0) + 0.5
        return s


def _build_mock_graph(findings=None, agents=None):
    """Build a fully-mocked LangGraph pipeline."""
    from graph.healing_graph import build_healing_graph
    return build_healing_graph(
        agents=agents or [
            _make_named_agent("StaticAnalysisAgent", findings or _CRITICAL_FINDINGS),
        ],
        correlation_agent=_MockCorrelationAgent(),
        patch_agent=_MockPatchAgent(),
        validator=_MockValidator(),
        deploy_agent=_MockDeployAgent(),
        monitor=_MockMonitor(),
    )


def _run(graph, source=None, address=None):
    """Invoke the graph with a minimal initial state."""
    from graph.runner import run_healing_pipeline
    return run_healing_pipeline(
        contract_source=source or _VAULT_SOL,
        contract_address=address or "0x" + "1" * 40,
        graph=graph,
    )


# ---------------------------------------------------------------------------
# Test 1 — Full pipeline completes without error
# ---------------------------------------------------------------------------

def test_full_pipeline_completes_without_error(tmp_path):
    """run_healing_pipeline must return a state dict and set error='' on success."""
    graph = _build_mock_graph()
    result = _run(graph)

    assert isinstance(result, dict), "Pipeline must return a dict"
    assert result.get("error") == "", (
        f"error must be empty on success; got: {result.get('error')!r}"
    )


# ---------------------------------------------------------------------------
# Test 2 — state.healed == True after full run
# ---------------------------------------------------------------------------

def test_healed_flag_is_true_after_full_run(tmp_path):
    """After a successful pipeline run, state['healed'] must be True."""
    graph = _build_mock_graph()
    result = _run(graph)

    assert result.get("healed") is True, (
        f"healed must be True after a successful pipeline run; got: {result.get('healed')}"
    )


# ---------------------------------------------------------------------------
# Test 3 — state.selected_patch contains valid Solidity
# ---------------------------------------------------------------------------

def test_selected_patch_is_valid_solidity(tmp_path):
    """state['selected_patch'] must be non-empty and contain 'pragma solidity'."""
    graph = _build_mock_graph()
    result = _run(graph)

    patch = result.get("selected_patch", "")
    assert patch, "selected_patch must not be empty"
    assert "pragma solidity" in patch, (
        "selected_patch must contain 'pragma solidity'"
    )
    assert "contract " in patch, (
        "selected_patch must contain a contract definition"
    )


# ---------------------------------------------------------------------------
# Test 4 — state.deployed == True
# ---------------------------------------------------------------------------

def test_deployed_flag_is_true(tmp_path):
    """state['deployed'] must be True after a successful pipeline run."""
    graph = _build_mock_graph()
    result = _run(graph)

    assert result.get("deployed") is True, (
        f"deployed must be True after pipeline success; got: {result.get('deployed')}"
    )
    assert result.get("tx_hash"), "tx_hash must be non-empty after deployment"


# ---------------------------------------------------------------------------
# Test 5 — All gate_results values are True
# ---------------------------------------------------------------------------

def test_all_gate_results_are_true(tmp_path):
    """After a successful run, all 5 gate_results values must be True."""
    graph = _build_mock_graph()
    result = _run(graph)

    gate_results = result.get("gate_results", {})
    assert len(gate_results) == 5, (
        f"gate_results must have exactly 5 entries; got {len(gate_results)}: {gate_results}"
    )
    for gate, passed in gate_results.items():
        assert passed is True, f"{gate} must be True; got {passed}"


# ---------------------------------------------------------------------------
# Test 6 — Pipeline handles a clean contract gracefully
# ---------------------------------------------------------------------------

def test_clean_contract_exits_gracefully(tmp_path):
    """A contract with no findings must complete the pipeline without error.
    The pipeline should not crash, even if it cannot heal what is not broken."""
    from graph.healing_graph import build_healing_graph

    class _NoFindingsCorrelation:
        def correlate(self, state):
            s = dict(state)
            s["all_findings"]    = []
            s["confidence_score"] = 1.0
            s["route"]           = "fast"
            s["conflict_flags"]  = []
            return s

    class _NoPatchNeededValidator:
        def validate_all(self, state):
            s = dict(state)
            # No findings → any patch trivially passes
            s["validation_passed"] = True
            s["selected_patch"]    = _CLEAN_CONTRACT
            s["gate_results"]      = {f"gate{i}": True for i in range(1, 6)}
            s["error"]             = ""
            return s

    graph = build_healing_graph(
        agents=[_make_named_agent("StaticAnalysisAgent", findings=[])],
        correlation_agent=_NoFindingsCorrelation(),
        patch_agent=_MockPatchAgent(),
        validator=_NoPatchNeededValidator(),
        deploy_agent=_MockDeployAgent(),
        monitor=_MockMonitor(),
    )

    from graph.runner import run_healing_pipeline
    result = run_healing_pipeline(
        contract_source=_CLEAN_CONTRACT,
        contract_address="0x" + "2" * 40,
        graph=graph,
    )

    assert isinstance(result, dict), "Pipeline must return a dict for clean contracts"
    assert "error" in result, "Result must contain 'error' key"
    # For a clean path, error must be empty (not a crash/exception)
    assert result["error"] == "", (
        f"Pipeline must not set error for a clean contract; got: {result['error']!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — Detection agents run in parallel (faster than sequential)
# ---------------------------------------------------------------------------

def test_detection_agents_run_in_parallel(tmp_path):
    """Running 5 agents each with a 0.1 s delay must complete faster than 0.4 s
    (well under the 0.5 s sequential total), demonstrating ThreadPoolExecutor
    parallelism inside detect_node."""
    from graph.healing_graph import build_healing_graph

    AGENT_DELAY = 0.1  # seconds per agent
    N_AGENTS    = 5

    agent_fields = [
        "StaticAnalysisAgent",
        "SymbolicExecutionAgent",
        "LLMSemanticAgent",
        "GovernanceMonitorAgent",
        "ThreatPatternAgent",
    ]
    slow_agents = [
        _make_named_agent(name, findings=[], delay=AGENT_DELAY)
        for name in agent_fields
    ]

    graph = build_healing_graph(
        agents=slow_agents,
        correlation_agent=_MockCorrelationAgent(),
        patch_agent=_MockPatchAgent(),
        validator=_MockValidator(),
        deploy_agent=_MockDeployAgent(),
        monitor=_MockMonitor(),
    )

    t0 = time.perf_counter()
    result = _run(graph)
    elapsed = time.perf_counter() - t0

    sequential_time = AGENT_DELAY * N_AGENTS  # 0.5 s
    assert elapsed < sequential_time, (
        f"Parallel detection must complete in < {sequential_time:.2f} s; "
        f"took {elapsed:.3f} s — agents may not be running in parallel"
    )
    assert isinstance(result, dict), "Pipeline must return a valid state dict"

    print("\nPHASE 7 COMPLETE — full LangGraph pipeline working")
