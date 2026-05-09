from dotenv import load_dotenv; load_dotenv()
from agents.static_agent import StaticAnalysisAgent
from agents.governance_agent import GovernanceMonitorAgent
from graph.correlation import CorrelationAgent, _SLOW_CONFIDENCE

src = open('contracts/VulnerableVault.sol').read()
state = {
    'pipeline_id': 'test', 'contract_source': src, 'contract_address': '0x1',
    'tvl_estimate': 0.0, 'static_findings': [], 'symbolic_findings': [],
    'semantic_findings': [], 'governance_findings': [], 'threat_findings': [],
    'all_findings': [], 'confidence_score': 0.0, 'route': 'medium',
    'conflict_flags': [], 'candidate_patches': [], 'selected_patch': '',
    'gate_results': {}, 'validation_passed': False, 'retry_count': 0,
    'deployed': False, 'tx_hash': '', 'rollback_target': '',
    'rl_reward': 0.0, 'healed': False, 'error': '', 'solidity_version': '0.8.22',
}

static = StaticAnalysisAgent().run(src, state)
gov    = GovernanceMonitorAgent()._pattern_findings(src)

print("Static findings:")
for f in static:
    print(f"  {f['vuln_type']} in {f['affected_function']}  conf={f['confidence']}  cross={f['cross_contract_flag']}  meth={f['methodology']}")

print("Governance findings:")
for f in gov:
    print(f"  {f['vuln_type']} in {f['affected_function']}  conf={f['confidence']}  meth={f['methodology']}")

state['static_findings'] = static
state['governance_findings'] = gov
state['symbolic_findings'] = [{
    'vuln_type': 'TIMEOUT', 'severity': 'Low', 'affected_function': 'unknown',
    'confidence': 0.0, 'methodology': 'symbolic', 'cross_contract_flag': False,
    'line_range': [0,0], 'fix_recommendation': '', 'evidence': 'myth not installed',
}]

ca = CorrelationAgent()
result = ca.correlate(state)

merged = result['all_findings']
print(f"\nMerged findings ({len(merged)}):")
for f in merged:
    print(f"  {f['vuln_type']} in {f['affected_function']}  conf={f['confidence']}  cross={f.get('cross_contract_flag')}  meth={f['methodology']}")

# Debug route conditions
cross = any(f.get("cross_contract_flag") for f in merged)
tvl   = float(state.get("tvl_estimate") or 0)
conf  = result['confidence_score']
novel = ca._has_novel_patterns(merged)

print(f"\n--- Route debug ---")
print(f"  confidence={conf:.3f}  threshold={_SLOW_CONFIDENCE}  below_threshold={conf < _SLOW_CONFIDENCE}")
print(f"  cross_contract={cross}")
print(f"  tvl={tvl}  high_tvl={tvl > 1_000_000}")
print(f"  has_novel_patterns={novel}")

print(f"\nConfidence: {result['confidence_score']:.1%}")
print(f"Route:      {result['route']}")
print(f"Conflicts:  {result['conflict_flags']}")
