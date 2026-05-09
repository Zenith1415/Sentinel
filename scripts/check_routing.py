"""Quick check — verify each contract routes correctly through the real pipeline."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path
from graph.correlation import CorrelationAgent
from agents.static_agent import StaticAnalysisAgent
from agents.symbolic_agent import SymbolicExecutionAgent
from agents.governance_agent import GovernanceMonitorAgent

CONTRACTS = {
    "VulnerableVault":   "contracts/VulnerableVault.sol",
    "UnpatchableVault":  "contracts/UnpatchableVault.sol",
    "SafeVault":         "contracts/SafeVault.sol",
}

def _empty_state():
    return {
        "pipeline_id": "test", "contract_source": "", "contract_address": "0x" + "0"*40,
        "solidity_version": "0.8.22", "tvl_estimate": 0.0,
        "static_findings": [], "symbolic_findings": [], "semantic_findings": [],
        "governance_findings": [], "threat_findings": [], "all_findings": [],
        "confidence_score": 0.0, "route": "medium", "conflict_flags": [],
        "candidate_patches": [], "selected_patch": "", "gate_results": {},
        "validation_passed": False, "retry_count": 0, "deployed": False,
        "tx_hash": "", "rollback_target": "", "rl_reward": 0.0,
        "healed": False, "error": "",
    }

print(f"{'Contract':22} {'Static':>8} {'Symbolic':>10} {'Gov':>5} {'Conf':>6}  Route")
print("─" * 70)

for name, path in CONTRACTS.items():
    src = Path(path).read_text(encoding="utf-8")
    state = _empty_state()
    state["contract_source"] = src

    static_findings   = StaticAnalysisAgent().run(src, state)
    symbolic_findings = SymbolicExecutionAgent().run(src, state)
    gov_findings      = GovernanceMonitorAgent()._pattern_findings(src)

    state["static_findings"]   = static_findings
    state["symbolic_findings"] = symbolic_findings
    state["governance_findings"] = gov_findings

    result = CorrelationAgent().correlate(state)
    route = result["route"]
    conf  = result["confidence_score"]

    color = {"fast": "\033[32m", "medium": "\033[33m", "slow": "\033[31m"}.get(route, "")
    reset = "\033[0m"
    print(f"{name:22} {len(static_findings):>8} {len(symbolic_findings):>10} {len(gov_findings):>5} {conf:>6.1%}  {color}{route.upper()}{reset}")
    for f in result["all_findings"]:
        print(f"   [{f['severity']:8}] {f['vuln_type']:30}  conf={f['confidence']:.0%}  cross={f.get('cross_contract_flag', False)}")
    print()
