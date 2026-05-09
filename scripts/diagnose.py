"""Run the full detection + correlation pipeline on each contract and dump
every finding from every agent so we can see why the confidence drops."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from pathlib import Path
from agents.static_agent      import StaticAnalysisAgent
from agents.symbolic_agent    import SymbolicExecutionAgent
from agents.semantic_agent    import LLMSemanticAgent
from agents.governance_agent  import GovernanceMonitorAgent
from agents.threat_pattern_agent import ThreatPatternAgent
from graph.correlation        import CorrelationAgent

CONTRACTS = ["SafeVault", "VulnerableVault", "UnpatchableVault"]

def empty_state():
    return {
        "pipeline_id": "diag", "contract_source": "", "contract_address": "0x" + "0"*40,
        "solidity_version": "0.8.22", "tvl_estimate": 0.0,
        "static_findings": [], "symbolic_findings": [], "semantic_findings": [],
        "governance_findings": [], "threat_findings": [], "all_findings": [],
        "confidence_score": 0.0, "route": "medium", "conflict_flags": [],
        "candidate_patches": [], "selected_patch": "", "gate_results": {},
        "validation_passed": False, "retry_count": 0, "deployed": False,
        "tx_hash": "", "rollback_target": "", "rl_reward": 0.0,
        "healed": False, "error": "",
    }

print("=" * 90)
for name in CONTRACTS:
    src = Path(f"contracts/{name}.sol").read_text(encoding="utf-8")
    state = empty_state()
    state["contract_source"] = src

    print(f"\n{'='*90}\n{name}\n{'='*90}")

    agents = [
        ("static",     StaticAnalysisAgent()),
        ("symbolic",   SymbolicExecutionAgent()),
        ("semantic",   LLMSemanticAgent()),
        ("governance", GovernanceMonitorAgent()),
        ("threat",     ThreatPatternAgent()),
    ]

    for label, agent in agents:
        try:
            findings = agent.run(src, state)
        except Exception as e:
            print(f"\n[{label:10}] ERROR: {e}")
            findings = []
        state[f"{label}_findings"] = findings
        print(f"\n[{label:10}] {len(findings)} findings")
        for f in findings[:6]:
            sev = f.get("severity", "?")
            vt  = f.get("vuln_type", "?")
            cf  = f.get("confidence", 0)
            xc  = f.get("cross_contract_flag", False)
            meth = f.get("methodology", "?")
            print(f"   [{sev:8}] {vt:34}  conf={cf:.0%}  cross={xc}  meth={meth}")

    result = CorrelationAgent().correlate(state)
    print(f"\n  Total findings:   {len(result.get('all_findings', []))}")
    print(f"  Confidence:       {result.get('confidence_score', 0):.1%}")
    print(f"  Route:            {result.get('route', '?').upper()}")
    print(f"  Conflicts:        {len(result.get('conflict_flags', []))}")
