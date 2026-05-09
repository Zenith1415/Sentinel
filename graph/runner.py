"""
runner.py — top-level entry point for the self-healing pipeline.

Usage:
    from graph.runner import run_healing_pipeline
    result = run_healing_pipeline(contract_source, contract_address)
"""
import uuid
import logging

from graph.state import HealingState
from graph.healing_graph import build_healing_graph

logger = logging.getLogger(__name__)


def run_healing_pipeline(
    contract_source: str,
    contract_address: str,
    solidity_version: str = "0.8.22",
    tvl_estimate: float = 0.0,
    pipeline_id: str | None = None,
    graph=None,
    **graph_kwargs,
) -> HealingState:
    """
    Execute the full healing pipeline for a Solidity contract.

    Parameters
    ----------
    contract_source   : raw Solidity source code
    contract_address  : deployed proxy address (0x…)
    solidity_version  : compiler version string
    tvl_estimate      : total value locked (USD) — used for routing
    pipeline_id       : optional stable ID; generated as UUID if omitted
    graph             : pre-compiled LangGraph (inject for testing)
    **graph_kwargs    : forwarded to build_healing_graph() when graph=None
    """
    if graph is None:
        graph = build_healing_graph(**graph_kwargs)

    initial_state: HealingState = {
        "pipeline_id":          pipeline_id or str(uuid.uuid4()),
        "contract_source":      contract_source,
        "contract_address":     contract_address,
        "solidity_version":     solidity_version,
        "tvl_estimate":         tvl_estimate,
        "static_findings":      [],
        "symbolic_findings":    [],
        "semantic_findings":    [],
        "governance_findings":  [],
        "threat_findings":      [],
        "all_findings":         [],
        "confidence_score":     0.0,
        "route":                "medium",
        "conflict_flags":       [],
        "candidate_patches":    [],
        "selected_patch":       "",
        "gate_results":         {},
        "validation_passed":    False,
        "retry_count":          0,
        "deployed":             False,
        "tx_hash":              "",
        "rollback_target":      "",
        "rl_reward":            0.0,
        "healed":               False,
        "error":                "",
    }

    import os
    from datetime import datetime
    os.environ["LANGCHAIN_PROJECT"] = (
        f"self-healing-{datetime.now().strftime('%H:%M')}"
    )

    logger.info("Starting healing pipeline %s", initial_state["pipeline_id"])
    result = graph.invoke(initial_state)
    logger.info(
        "Pipeline %s finished — healed=%s deployed=%s error=%s",
        initial_state["pipeline_id"],
        result.get("healed"),
        result.get("deployed"),
        result.get("error") or "none",
    )
    return result
