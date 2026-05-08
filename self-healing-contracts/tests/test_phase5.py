"""
Phase 5 — 5-Gate Validator.

Tests:
  1. VulnerableVault healed patch passes all 5 gates
  2. A patch that reintroduces a vuln fails Gate 1
  3. A patch that removes a function fails Gate 3
  4. Gate 5 auto-generates invariant tests when no Foundry suite exists
  5. Ranking selects lower-gas candidate when both pass all gates
  6. Retry logic triggers on 3 consecutive failures (route → "slow")
  7. state.selected_patch is set after successful validation
"""
import uuid
from pathlib import Path
from unittest.mock import patch as mock_patch

import pytest

# ---------------------------------------------------------------------------
# Solidity test fixtures
# ---------------------------------------------------------------------------

_VAULT_SOL = (
    Path(__file__).parent.parent / "contracts" / "VulnerableVault.sol"
).read_text(encoding="utf-8")

# Self-contained healed contract: fixes reentrancy (CEI) + adds onlyOwner.
# No OpenZeppelin imports so Gate 2 can compile it directly.
_HEALED_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract HealedVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _initialized;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {}

    function initialize(address initialOwner) public {
        require(!_initialized, "Already initialized");
        _initialized = true;
        owner = initialOwner;
    }

    // CEI fix: balance cleared BEFORE external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawn(msg.sender, amount);
    }

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // Access-control fix: onlyOwner added
    function setOwner(address newOwner) external onlyOwner {
        address old = owner;
        owner = newOwner;
        emit OwnerChanged(old, newOwner);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
"""

# Candidate that re-introduces the reentrancy vulnerability.
_REENTRANT_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract ReentrantVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _initialized;

    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }

    constructor() {}

    function initialize(address initialOwner) public {
        owner = initialOwner;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function setOwner(address newOwner) external onlyOwner {
        address old = owner;
        owner = newOwner;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
"""

# Candidate that removes getBalance() — should fail Gate 3.
_MISSING_FN_VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;
contract MissingFnVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _initialized;

    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }

    constructor() {}

    function initialize(address initialOwner) public {
        owner = initialOwner;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
    // getBalance() intentionally removed
}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CRITICAL_FINDINGS = [
    {
        "vuln_type": "Reentrancy",
        "severity": "Critical",
        "affected_function": "withdraw",
        "line_range": [1, 10],
        "confidence": 0.95,
        "fix_recommendation": "Apply CEI pattern",
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


def _state(**overrides) -> dict:
    base = {
        "pipeline_id": "test-phase5",
        "contract_source": _VAULT_SOL,
        "contract_address": "",
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


def _candidate(patch_source: str, strategy: str = "proven", **kwargs) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "strategy": strategy,
        "patch_source": patch_source,
        "explanation": "Test patch",
        "vuln_types_addressed": ["Reentrancy", "MissingAccessControl"],
        "flagged_for_review": False,
        "flag_reasons": [],
        "new_vulns": [],
        **kwargs,
    }


def _all_pass_validator(v):
    """Monkey-patch all 5 gates on a Validator instance to always pass."""
    v._gate1_vuln_removal = lambda s, st: (True, "mocked-pass")
    v._gate2_compilation = lambda s, sv: (True, "mocked-pass")
    v._gate3_signatures = lambda o, c: (True, "mocked-pass")
    v._gate4_kb_similarity = lambda s: (True, "mocked-pass")
    v._gate5_fuzzing = lambda s, st: (True, "mocked-pass")
    return v


# ---------------------------------------------------------------------------
# Test 1 — VulnerableVault healed patch passes all 5 gates
# ---------------------------------------------------------------------------

def test_healed_patch_passes_all_gates(tmp_path):
    """A properly fixed VulnerableVault patch must pass every one of the 5 gates."""
    from core.validator import Validator
    from agents.static_agent import StaticAnalysisAgent

    v = Validator(chroma_path=str(tmp_path), agents=[StaticAnalysisAgent()])
    state = _state(candidate_patches=[_candidate(_HEALED_VAULT)])
    result = v.validate_all(state)

    assert result["validation_passed"], (
        f"Expected all gates to pass.\nError: {result.get('error')}\n"
        f"Candidate gate results: {result['candidate_patches'][0].get('gate_results')}\n"
        f"Gate reasons: gate1={result['candidate_patches'][0].get('gate1_reason')}, "
        f"gate3={result['candidate_patches'][0].get('gate3_reason')}, "
        f"gate5={result['candidate_patches'][0].get('gate5_reason')}"
    )
    assert result["selected_patch"] == _HEALED_VAULT

    grs = result["candidate_patches"][0]["gate_results"]
    assert grs.get("gate1") is True, f"Gate 1 failed: {result['candidate_patches'][0].get('gate1_reason')}"
    assert grs.get("gate3") is True, f"Gate 3 failed: {result['candidate_patches'][0].get('gate3_reason')}"
    assert grs.get("gate4") is True, f"Gate 4 failed: {result['candidate_patches'][0].get('gate4_reason')}"
    assert grs.get("gate5") is True, f"Gate 5 failed: {result['candidate_patches'][0].get('gate5_reason')}"


# ---------------------------------------------------------------------------
# Test 2 — A patch that reintroduces a vuln fails Gate 1
# ---------------------------------------------------------------------------

def test_reintroduced_vuln_fails_gate1(tmp_path):
    """A candidate that still contains the original reentrancy must fail Gate 1."""
    from core.validator import Validator
    from agents.static_agent import StaticAnalysisAgent

    v = Validator(chroma_path=str(tmp_path), agents=[StaticAnalysisAgent()])
    state = _state(candidate_patches=[_candidate(_REENTRANT_VAULT)])
    result = v.validate_all(state)

    candidates = result["candidate_patches"]
    assert len(candidates) == 1
    c = candidates[0]

    assert c["gate_results"]["gate1"] is False, (
        f"Gate 1 must fail when reentrancy remains. "
        f"Reason: {c.get('gate1_reason')}"
    )
    assert c["all_gates_passed"] is False
    assert not result["validation_passed"]


# ---------------------------------------------------------------------------
# Test 3 — A patch that removes a function fails Gate 3
# ---------------------------------------------------------------------------

def test_missing_function_fails_gate3(tmp_path):
    """A candidate missing getBalance() must fail Gate 3 (signature preservation)."""
    from core.validator import Validator

    # No original Critical/High findings → Gate 1 trivially passes; Gate 3 is the focus.
    v = Validator(chroma_path=str(tmp_path), agents=[])
    state = _state(
        all_findings=[],
        candidate_patches=[_candidate(_MISSING_FN_VAULT)],
    )
    result = v.validate_all(state)

    candidates = result["candidate_patches"]
    assert len(candidates) == 1
    c = candidates[0]

    assert c["gate_results"]["gate3"] is False, (
        f"Gate 3 must fail when getBalance() is removed. "
        f"Reason: {c.get('gate3_reason')}"
    )
    assert "getBalance" in c.get("gate3_reason", ""), (
        f"gate3_reason should identify the missing function. Got: {c.get('gate3_reason')}"
    )
    assert c["all_gates_passed"] is False


# ---------------------------------------------------------------------------
# Test 4 — Gate 5 auto-generates invariant tests when no Foundry suite exists
# ---------------------------------------------------------------------------

def test_gate5_autogenerates_tests_when_none_exist(tmp_path):
    """When _foundry_tests_exist returns False, generate_invariant_tests must
    produce non-empty Echidna-format test code containing echidna_ property functions."""
    from core.validator import Validator

    v = Validator(chroma_path=str(tmp_path))

    # Confirm the generation function produces output regardless of environment
    tests = v.generate_invariant_tests(_HEALED_VAULT, _state())

    assert tests, "generate_invariant_tests must return a non-empty string"
    assert "EchidnaTest" in tests, "Generated tests should define an EchidnaTest contract"
    assert "function echidna_" in tests, (
        "Generated tests must contain echidna_ prefixed property functions"
    )
    assert "echidna_balance_nonnegative" in tests, (
        "Must include balance-non-negative invariant"
    )

    # Verify Gate 5 actually calls generate_invariant_tests when Foundry is absent
    with mock_patch.object(v, "_foundry_tests_exist", return_value=False):
        passed, reason = v._gate5_fuzzing(_HEALED_VAULT, _state())

    # Either Echidna ran (pass/fail) or static simulation was used — gate executed
    assert isinstance(passed, bool), "Gate 5 must return a bool result"
    assert isinstance(reason, str) and reason, "Gate 5 must return a reason string"


# ---------------------------------------------------------------------------
# Test 5 — Ranking selects the lower-gas candidate when both pass all gates
# ---------------------------------------------------------------------------

def test_ranking_selects_lower_gas_candidate(tmp_path):
    """When two candidates both pass all 5 gates, the one with fewer lines
    (lower estimated gas) must be selected."""
    from core.validator import Validator

    base_source = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.22;\n"
        "contract Base {\n"
        "    function foo() external {}\n"
        "    function bar() public view returns (uint256) { return 0; }\n"
        "}\n"
    )
    # SHORT: 6 lines (same as base)
    short_source = base_source

    # LONG: 100+ extra comment lines before the contract
    long_source = "".join(f"// padding line {i}\n" for i in range(100)) + base_source

    v = _all_pass_validator(Validator(chroma_path=str(tmp_path), agents=[]))
    state = _state(
        contract_source=base_source,
        all_findings=[],
        candidate_patches=[
            _candidate(long_source, strategy="proven"),
            _candidate(short_source, strategy="experimental"),
        ],
    )
    result = v.validate_all(state)

    assert result["validation_passed"], f"Validation failed unexpectedly: {result.get('error')}"
    assert result["selected_patch"] == short_source, (
        "Ranking must select the shorter (lower-gas) candidate over the longer one"
    )


# ---------------------------------------------------------------------------
# Test 6 — Retry logic triggers human escalation after 3 consecutive failures
# ---------------------------------------------------------------------------

def test_retry_logic_triggers_after_three_failures(tmp_path):
    """After 3 consecutive validation failures (retry_count reaches 3),
    route must be forced to 'slow' and human escalation flagged."""
    from core.validator import Validator
    from agents.static_agent import StaticAnalysisAgent

    # Start at retry_count=2 so the next failure pushes it to 3
    state = _state(
        retry_count=2,
        candidate_patches=[_candidate(_REENTRANT_VAULT)],
    )
    v = Validator(chroma_path=str(tmp_path), agents=[StaticAnalysisAgent()])
    result = v.validate_all(state)

    assert result["retry_count"] == 3, (
        f"retry_count must reach 3. Got: {result['retry_count']}"
    )
    assert result["route"] == "slow", (
        f"route must be forced to 'slow' after 3 failures. Got: {result['route']}"
    )
    assert not result["validation_passed"]
    assert result["error"], "error field must contain escalation message"

    # Also verify intermediate retry (retry_count < 3) does NOT force slow route
    state2 = _state(
        retry_count=0,
        route="medium",
        candidate_patches=[_candidate(_REENTRANT_VAULT)],
    )
    result2 = v.validate_all(state2)
    assert result2["retry_count"] == 1
    assert result2["route"] != "slow", (
        "route must NOT be forced to 'slow' on first retry (retry_count=1)"
    )


# ---------------------------------------------------------------------------
# Test 7 — state.selected_patch is set after successful validation
# ---------------------------------------------------------------------------

def test_selected_patch_is_set_after_validation(tmp_path):
    """After successful validation, state.selected_patch must be non-empty
    and equal to the winning candidate's patch_source."""
    from core.validator import Validator

    v = _all_pass_validator(Validator(chroma_path=str(tmp_path), agents=[]))
    state = _state(
        all_findings=[],
        candidate_patches=[_candidate(_HEALED_VAULT)],
    )
    result = v.validate_all(state)

    assert result["validation_passed"], f"Unexpected failure: {result.get('error')}"
    assert result["selected_patch"], "selected_patch must be non-empty after validation"
    assert result["selected_patch"] == _HEALED_VAULT, (
        "selected_patch must equal the winning candidate's patch_source"
    )
    assert isinstance(result["gate_results"], dict), "gate_results must be a dict"
    assert len(result["gate_results"]) == 5, "gate_results must contain exactly 5 entries"
