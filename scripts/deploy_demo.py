"""
Demo script — deploys VulnerableVault via UUPS proxy, then runs the healing pipeline.
Usage: python scripts/deploy_demo.py
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv()

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from pathlib import Path
from graph.healing_graph import healing_graph
from graph.state import HealingState
from core.kb import KnowledgeBase


def main():
    w3 = Web3(Web3.HTTPProvider(os.environ["RPC_URL"]))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    print(f"Connected: {w3.is_connected()} | Block: {w3.eth.block_number}")

    # Seed KB
    kb = KnowledgeBase()
    kb.seed_defaults()
    print("Knowledge base seeded.")

    # Load vulnerable contract source
    src_path = Path(__file__).parent.parent / "contracts" / "VulnerableVault.sol"
    source = src_path.read_text()

    # Run healing pipeline (no on-chain deploy in demo — contract_address=None)
    state = HealingState(
        contract_source=source,
        contract_address=None,
        static_findings=[], symbolic_findings=[], semantic_findings=[],
        threat_patterns=[], all_findings=[],
        patched_source=None, patch_diff=None,
        governance_approved=False, governance_notes="",
        gate_syntax_ok=False, gate_tests_ok=False,
        gate_slither_ok=False, gate_gas_ok=False, gate_governance_ok=False,
        new_implementation_address=None, upgrade_tx_hash=None, deploy_error=None,
        iteration=0, max_iterations=3, status="running",
    )

    print("\nStarting healing pipeline...\n")
    result = healing_graph.invoke(state)

    print(f"\nStatus     : {result['status']}")
    print(f"Findings   : {len(result['all_findings'])}")
    print(f"Gov approved: {result['governance_approved']}")
    if result.get("patch_diff"):
        print("\n--- PATCH DIFF (first 60 lines) ---")
        diff_lines = result["patch_diff"].splitlines()[:60]
        print("\n".join(diff_lines))

    if result["status"] == "healed":
        print("\nPHASE 0 COMPLETE — all imports ok, contracts compile")
    else:
        print("\nPipeline finished with status:", result["status"])


if __name__ == "__main__":
    main()
