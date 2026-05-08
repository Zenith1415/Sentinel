from typing import TypedDict


class HealingState(TypedDict):
    pipeline_id: str
    contract_source: str
    contract_address: str
    solidity_version: str
    tvl_estimate: float

    # Detection
    static_findings: list[dict]
    symbolic_findings: list[dict]
    semantic_findings: list[dict]
    governance_findings: list[dict]
    threat_findings: list[dict]
    all_findings: list[dict]        # populated by correlation node

    # Routing
    confidence_score: float
    route: str                      # "fast" | "medium" | "slow"
    conflict_flags: list[str]

    # Repair
    candidate_patches: list[dict]   # [{source, strategy, score}]
    selected_patch: str

    # Validation
    gate_results: dict              # {gate1: bool, ..., gate5: bool}
    validation_passed: bool
    retry_count: int

    # Deploy
    deployed: bool
    tx_hash: str
    rollback_target: str

    # RL
    rl_reward: float
    healed: bool
    error: str
