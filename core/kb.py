"""
Knowledge Base — ChromaDB (local) + MongoDB Atlas Vector Search (cloud).

Writes go to both stores. Reads hit Atlas first; ChromaDB is the fallback.
If MONGODB_URI is not set, Atlas is silently skipped.
"""
import logging
import os
from typing import List, Dict, Any
import chromadb

logger = logging.getLogger(__name__)


def _make_atlas(collection_name: str):
    """Return a MongoVectorStore or None if not configured."""
    uri = os.getenv("MONGODB_URI", "")
    if not uri:
        return None
    try:
        from core.mongo_vector_store import MongoVectorStore
        db = os.getenv("MONGODB_DB", "self_healing_contracts")
        return MongoVectorStore(uri, db, collection_name)
    except Exception as exc:
        logger.warning("MongoDB Atlas init failed — local-only mode: %s", exc)
        return None


class KnowledgeBase:
    COLLECTION = "vuln_patterns"

    def __init__(self, path: str | None = None):
        chroma_path = path or os.getenv("CHROMA_PATH", "./chroma_db")
        self._client = chromadb.PersistentClient(path=chroma_path)
        self._col = self._client.get_or_create_collection(self.COLLECTION)
        self._atlas = _make_atlas(self.COLLECTION)

    def seed_defaults(self) -> None:
        patterns = [
            {
                "id": "KB-REENT-001",
                "severity": "critical",
                "type": "reentrancy",
                "location": "withdraw",
                "description": (
                    "External call before state update enables reentrancy. "
                    "Attacker's fallback re-enters withdraw() and drains funds."
                ),
                "suggested_fix": "Use CEI: update balances[msg.sender] = 0 BEFORE .call{value:}.",
                "code_pattern": ".call{value:} before balances update reentrancy external call",
            },
            {
                "id": "KB-ACC-001",
                "severity": "critical",
                "type": "access_control",
                "location": "setOwner",
                "description": "Privileged function missing onlyOwner or equivalent modifier.",
                "suggested_fix": "Add onlyOwner modifier.",
                "code_pattern": "function setOwner without onlyOwner access control missing",
            },
            {
                "id": "KB-INT-001",
                "severity": "high",
                "type": "integer_overflow",
                "location": "arithmetic",
                "description": "Unchecked arithmetic may overflow on older Solidity versions.",
                "suggested_fix": "Use Solidity >=0.8.0 built-in overflow checks or SafeMath.",
                "code_pattern": "unchecked arithmetic overflow uint256 addition subtraction",
            },
            {
                "id": "KB-OWN-001",
                "severity": "critical",
                "type": "ownership_hijacking",
                "location": "setOwner",
                "description": "Ownership transfer function missing access control — any caller can hijack.",
                "suggested_fix": "Add onlyOwner modifier to prevent unauthorized ownership transfer.",
                "code_pattern": "ownership hijacking missing access control setOwner transferOwnership",
            },
            {
                "id": "KB-INIT-001",
                "severity": "critical",
                "type": "unprotected_initializer",
                "location": "initialize",
                "description": "Initializer function missing the initializer modifier — can be called multiple times.",
                "suggested_fix": "Add OpenZeppelin initializer modifier to restrict single invocation.",
                "code_pattern": "initializer modifier missing initialize function upgradeable proxy",
            },
            {
                "id": "KB-TX-001",
                "severity": "high",
                "type": "tx_origin_auth",
                "location": "unknown",
                "description": "Using tx.origin for authorization instead of msg.sender.",
                "suggested_fix": "Replace tx.origin with msg.sender for all auth checks.",
                "code_pattern": "tx.origin authorization authentication phishing attack",
            },
            # ── Patterns from kadenzipfel/smart-contract-vulnerabilities ──────
            {
                "id": "KB-STOR-001",
                "severity": "high",
                "type": "arbitrary_storage_location",
                "location": "unknown",
                "description": "Writes to a storage slot computed from user input can overwrite arbitrary state including owner / mappings.",
                "suggested_fix": "Never derive storage slots from untrusted input; use fixed mappings keyed by msg.sender or hashed namespaces.",
                "code_pattern": "arbitrary storage write user controlled slot sstore assembly",
            },
            {
                "id": "KB-ASSERT-001",
                "severity": "medium",
                "type": "assert_violation",
                "location": "unknown",
                "description": "assert() used for input validation consumes all gas on failure and signals an invariant break to off-chain monitors.",
                "suggested_fix": "Use require() for input/precondition checks; reserve assert() for genuine invariants that must never fail.",
                "code_pattern": "assert require misuse input validation invariant panic",
            },
            {
                "id": "KB-CSIZE-001",
                "severity": "medium",
                "type": "code_size_check",
                "location": "unknown",
                "description": "extcodesize == 0 used to detect EOAs is bypassable: during construction a contract has zero code size, and tx.origin == msg.sender checks fail under account abstraction.",
                "suggested_fix": "Do not rely on extcodesize to gate behavior; design so contract callers are acceptable, or use an allowlist.",
                "code_pattern": "extcodesize EOA check contract detection bypass constructor",
            },
            {
                "id": "KB-VIS-001",
                "severity": "high",
                "type": "default_visibility",
                "location": "unknown",
                "description": "Function or state variable lacks an explicit visibility specifier; pre-0.5.0 defaults to public, exposing privileged logic.",
                "suggested_fix": "Always declare explicit visibility (external/public/internal/private). Pin compiler to >=0.5.0 which enforces this.",
                "code_pattern": "default visibility public function state variable missing modifier",
            },
            {
                "id": "KB-DEL-001",
                "severity": "critical",
                "type": "delegatecall_untrusted",
                "location": "unknown",
                "description": "delegatecall to an attacker-controlled or upgradeable address executes foreign code in this contract's storage context — full takeover.",
                "suggested_fix": "Only delegatecall to trusted, immutable libraries. Validate target against an allowlist; never accept the target as a parameter.",
                "code_pattern": "delegatecall untrusted target arbitrary code storage hijack",
            },
            {
                "id": "KB-DOS-001",
                "severity": "high",
                "type": "dos_gas_limit",
                "location": "unknown",
                "description": "Unbounded loops over user-growable arrays can exceed the block gas limit, permanently bricking the function.",
                "suggested_fix": "Cap iteration counts, use pull-over-push payment patterns, or paginate over the array.",
                "code_pattern": "unbounded loop array iteration gas limit denial of service",
            },
            {
                "id": "KB-DOS-002",
                "severity": "high",
                "type": "dos_revert",
                "location": "unknown",
                "description": "A push-payment loop that reverts on a single failed transfer lets one malicious recipient block payouts to everyone.",
                "suggested_fix": "Use pull-payment pattern: each recipient withdraws their own balance, isolating failures.",
                "code_pattern": "push payment revert loop recipient denial of service withdraw",
            },
            {
                "id": "KB-PRAG-001",
                "severity": "low",
                "type": "floating_pragma",
                "location": "pragma",
                "description": "pragma solidity ^0.8.0 lets the contract compile with any future minor version, which may behave differently than the audited build.",
                "suggested_fix": "Lock the pragma to the exact version used during audit, e.g. pragma solidity 0.8.22;.",
                "code_pattern": "floating pragma caret version compiler audit mismatch",
            },
            {
                "id": "KB-HASH-001",
                "severity": "high",
                "type": "hash_collision",
                "location": "unknown",
                "description": "abi.encodePacked with two or more variable-length arguments can produce identical hashes for different inputs (e.g. ['a','bc'] and ['ab','c']).",
                "suggested_fix": "Use abi.encode (fixed-width slot encoding) when hashing, or include length prefixes / fixed-length arguments.",
                "code_pattern": "abi.encodePacked hash collision keccak variable length signature",
            },
            {
                "id": "KB-STD-001",
                "severity": "medium",
                "type": "non_standard_implementation",
                "location": "unknown",
                "description": "Token / interface implementation deviates from the spec (e.g. ERC-20 transfer returns nothing instead of bool), breaking integrators.",
                "suggested_fix": "Conform exactly to the published interface; use OpenZeppelin's reference implementations.",
                "code_pattern": "non standard ERC20 ERC721 interface deviation return value missing",
            },
            {
                "id": "KB-CTOR-001",
                "severity": "critical",
                "type": "incorrect_constructor",
                "location": "constructor",
                "description": "Pre-0.4.22 'constructor' was a function with the same name as the contract; a typo turns it into a public method anyone can call.",
                "suggested_fix": "Use the constructor keyword (Solidity >=0.4.22). Pin the pragma to a recent version.",
                "code_pattern": "constructor name typo public function takeover legacy",
            },
            {
                "id": "KB-INH-001",
                "severity": "medium",
                "type": "incorrect_inheritance_order",
                "location": "contract_declaration",
                "description": "Solidity linearizes inheritance right-to-left; declaring base contracts in the wrong order shadows the wrong functions and breaks expected overrides.",
                "suggested_fix": "List base contracts most-base to most-derived; use override / virtual explicitly. Run slither inheritance-graph.",
                "code_pattern": "inheritance order C3 linearization shadow override base contract",
            },
            {
                "id": "KB-GAS-001",
                "severity": "medium",
                "type": "insufficient_gas_griefing",
                "location": "unknown",
                "description": "Relayed call forwards only part of the available gas; attacker-set low gas makes the inner call fail silently while the outer tx still succeeds.",
                "suggested_fix": "Forward all remaining gas (call{gas: gasleft()}) or check the inner call's success and revert if it ran out of gas.",
                "code_pattern": "gas griefing relayer 1/64 forwarding partial inner call",
            },
            {
                "id": "KB-PREC-001",
                "severity": "medium",
                "type": "lack_of_precision",
                "location": "arithmetic",
                "description": "Integer division truncates; performing division before multiplication discards precision and amplifies rounding errors.",
                "suggested_fix": "Always multiply before dividing. Use scale factors / fixed-point libraries (e.g. PRBMath) for fractional math.",
                "code_pattern": "integer division precision loss truncation order operations rounding",
            },
            {
                "id": "KB-SIG-001",
                "severity": "high",
                "type": "signature_replay",
                "location": "unknown",
                "description": "Signed message accepted without nonce or chain-id binding can be replayed across transactions, contracts, or chains.",
                "suggested_fix": "Include a per-signer nonce and chainid (EIP-712 domain separator) in the signed payload; mark used signatures.",
                "code_pattern": "signature replay nonce chainid EIP-712 domain separator missing",
            },
            {
                "id": "KB-MSGV-001",
                "severity": "high",
                "type": "msg_value_in_loop",
                "location": "unknown",
                "description": "msg.value is constant for the whole transaction; using it inside a loop credits the same ETH to multiple iterations, allowing free duplication.",
                "suggested_fix": "Read msg.value once outside the loop and divide / track explicitly per iteration.",
                "code_pattern": "msg.value loop iteration duplicate credit payable batch",
            },
            {
                "id": "KB-OBO-001",
                "severity": "medium",
                "type": "off_by_one",
                "location": "unknown",
                "description": "Loop bound or comparison uses < where <= is required (or vice versa), missing the last element or over-running.",
                "suggested_fix": "Audit boundary conditions; prefer < length idioms; add unit tests at len-1, len, len+1.",
                "code_pattern": "off by one loop boundary length comparison index out of range",
            },
            {
                "id": "KB-COMP-001",
                "severity": "medium",
                "type": "outdated_compiler",
                "location": "pragma",
                "description": "Old Solidity compilers contain known bugs (e.g. ABI re-encoder corruption, dirty high-bits) fixed in later releases.",
                "suggested_fix": "Use a current compiler version; consult solidity-bug-list and upgrade.",
                "code_pattern": "outdated solidity compiler version known bug pragma upgrade",
            },
            {
                "id": "KB-REQ-001",
                "severity": "low",
                "type": "requirement_violation",
                "location": "unknown",
                "description": "Public function reverts on inputs the caller cannot pre-check, indicating a leaked internal precondition.",
                "suggested_fix": "Either expose a view to verify preconditions, or document inputs and validate at the boundary so failures are caller errors.",
                "code_pattern": "require violation external input precondition leaked invariant",
            },
            {
                "id": "KB-SHAD-001",
                "severity": "medium",
                "type": "shadowing_state_variables",
                "location": "unknown",
                "description": "Derived contract declares a state variable with the same name as a parent's, shadowing it; reads/writes hit different slots than intended.",
                "suggested_fix": "Rename or remove duplicates. Solidity >=0.6.0 warns; treat warnings as errors in CI.",
                "code_pattern": "shadow state variable inheritance same name slot mismatch",
            },
            {
                "id": "KB-SIG-002",
                "severity": "high",
                "type": "signature_malleability",
                "location": "unknown",
                "description": "ecrecover accepts both (r,s,v) and (r,n-s,v') for the same message, so signatures used as uniqueness keys are forgeable variants.",
                "suggested_fix": "Use OpenZeppelin ECDSA which rejects high-s values, or check s <= secp256k1n/2.",
                "code_pattern": "signature malleability ecrecover high s low s ECDSA",
            },
            {
                "id": "KB-TIME-001",
                "severity": "medium",
                "type": "timestamp_dependence",
                "location": "unknown",
                "description": "block.timestamp can be manipulated by miners by ~15 seconds; using it as a randomness source or precise gate is exploitable.",
                "suggested_fix": "Avoid sub-minute timing logic; use block numbers for relative ordering; use a VRF / commit-reveal for randomness.",
                "code_pattern": "block.timestamp now miner manipulation randomness time gate",
            },
            {
                "id": "KB-TOD-001",
                "severity": "high",
                "type": "transaction_ordering_dependence",
                "location": "unknown",
                "description": "Outcome depends on the order transactions are mined (front-running). E.g. updating a price after observing a pending swap.",
                "suggested_fix": "Use commit-reveal, slippage tolerances, batch auctions, or private mempools (Flashbots) for sensitive flows.",
                "code_pattern": "front running transaction order MEV pending mempool sandwich",
            },
            {
                "id": "KB-RET-001",
                "severity": "medium",
                "type": "unbounded_return_data",
                "location": "unknown",
                "description": "External call's returndatacopy with attacker-controlled length can OOM the caller, causing DoS via returnbomb.",
                "suggested_fix": "Use try/catch with a bounded returndata copy, or assembly with a fixed returndatacopy length.",
                "code_pattern": "return bomb returndata unbounded copy DoS external call",
            },
            {
                "id": "KB-RET-002",
                "severity": "high",
                "type": "unchecked_return_value",
                "location": "unknown",
                "description": "Low-level send/call/transfer or non-reverting ERC20 returns a bool that, if ignored, lets failures pass silently.",
                "suggested_fix": "Always check the returned bool; for ERC20 use OpenZeppelin SafeERC20.safeTransfer.",
                "code_pattern": "unchecked return value send call transfer ERC20 SafeERC20",
            },
            {
                "id": "KB-PRIV-001",
                "severity": "high",
                "type": "private_data_onchain",
                "location": "unknown",
                "description": "'private' visibility hides data from other contracts but not from anyone reading chain state — sealed bids, secrets, etc. are public.",
                "suggested_fix": "Never store secrets on-chain in plaintext. Use commit-reveal hashes or off-chain encryption with on-chain commitment.",
                "code_pattern": "private visibility on chain secret bid storage slot exposed",
            },
            {
                "id": "KB-ECR-001",
                "severity": "high",
                "type": "ecrecover_null_address",
                "location": "unknown",
                "description": "ecrecover returns address(0) on invalid signatures; comparing against an uninitialized signer field lets attackers authenticate as 0x0.",
                "suggested_fix": "Reject address(0) explicitly: require(signer != address(0) && recovered == signer).",
                "code_pattern": "ecrecover null address zero invalid signature uninitialized signer",
            },
            {
                "id": "KB-USP-001",
                "severity": "critical",
                "type": "uninitialized_storage_pointer",
                "location": "unknown",
                "description": "Local struct declared without 'memory' aliases storage slot 0 (pre-0.5.0), letting writes corrupt the first state variable (often owner).",
                "suggested_fix": "Use 'memory' or 'storage' explicitly. Pin compiler >=0.5.0 which makes this a hard error.",
                "code_pattern": "uninitialized storage pointer local struct slot zero owner overwrite",
            },
            {
                "id": "KB-LOW-001",
                "severity": "high",
                "type": "unsafe_low_level_call",
                "location": "unknown",
                "description": "Raw .call / .delegatecall without checking success or restricting target enables arbitrary external execution and silent failures.",
                "suggested_fix": "Prefer typed interfaces; if .call is required, check success, restrict targets, and forward only necessary calldata.",
                "code_pattern": "low level call delegatecall raw unchecked target arbitrary",
            },
            {
                "id": "KB-SIG-003",
                "severity": "high",
                "type": "unsecure_signature_scheme",
                "location": "unknown",
                "description": "Signing scheme omits domain separation, contract address, or function selector — a signature for one purpose is reusable for another.",
                "suggested_fix": "Use EIP-712 typed-data signing with full domain separator (name, version, chainid, contract).",
                "code_pattern": "unsecure signature scheme EIP-712 domain separation cross function reuse",
            },
            {
                "id": "KB-OPC-001",
                "severity": "medium",
                "type": "unsupported_opcodes",
                "location": "unknown",
                "description": "Contract uses opcodes (PUSH0, MCOPY, BASEFEE, etc.) not supported on the target L2 / sidechain, causing deploy or runtime failure.",
                "suggested_fix": "Match compiler EVM target (--evm-version) to the destination chain; test deploys on the target network.",
                "code_pattern": "unsupported opcode PUSH0 BASEFEE evm version L2 sidechain",
            },
            {
                "id": "KB-UNUSED-001",
                "severity": "low",
                "type": "unused_variables",
                "location": "unknown",
                "description": "Unused variables, parameters, or return values often signal incomplete logic or copy-paste bugs left after refactoring.",
                "suggested_fix": "Remove dead variables; treat solc warnings as errors in CI.",
                "code_pattern": "unused variable parameter return value dead code refactor",
            },
            {
                "id": "KB-DEPR-001",
                "severity": "medium",
                "type": "deprecated_functions",
                "location": "unknown",
                "description": "Use of deprecated functions (suicide, sha3, throw, callcode, block.blockhash, var) — semantics may change or be removed.",
                "suggested_fix": "Replace with current equivalents: selfdestruct, keccak256, revert, delegatecall, blockhash, explicit types.",
                "code_pattern": "deprecated function suicide sha3 throw callcode var solidity legacy",
            },
            {
                "id": "KB-RAND-001",
                "severity": "high",
                "type": "weak_randomness",
                "location": "unknown",
                "description": "block.timestamp, block.difficulty/prevrandao, blockhash and similar on-chain values are predictable / miner-influenceable; using them for randomness lets attackers win lotteries or mint rare NFTs deterministically.",
                "suggested_fix": "Use a verifiable randomness source (Chainlink VRF) or commit-reveal with bonded participants.",
                "code_pattern": "weak randomness block.timestamp blockhash prevrandao predictable VRF",
            },
        ]
        ids = [p["id"] for p in patterns]
        docs = [p["code_pattern"] for p in patterns]
        metas = [{k: v for k, v in p.items() if k != "code_pattern"} for p in patterns]
        self._col.upsert(ids=ids, documents=docs, metadatas=metas)
        if self._atlas:
            try:
                self._atlas.upsert(ids, docs, metas)
            except Exception as exc:
                logger.warning("Atlas seed failed — local KB still seeded: %s", exc)

    def query(self, text: str, n_results: int = 3) -> List[Dict[str, Any]]:
        # Try Atlas first
        if self._atlas:
            try:
                atlas_results = self._atlas.query(text, n_results)
                if atlas_results:
                    return atlas_results
            except Exception as exc:
                logger.warning("Atlas query failed — falling back to ChromaDB: %s", exc)

        # ChromaDB fallback
        count = self._col.count()
        if count == 0:
            return []
        actual_n = min(n_results, count)
        results = self._col.query(query_texts=[text], n_results=actual_n)
        out = []
        for i, meta in enumerate(results.get("metadatas", [[]])[0]):
            score = results["distances"][0][i] if results.get("distances") else 1.0
            out.append({**meta, "score": score})
        return out

    def add_pattern(self, pattern: Dict[str, Any]) -> None:
        doc = pattern.get("code_pattern", pattern["description"])
        meta = {k: v for k, v in pattern.items() if k != "code_pattern"}
        self._col.upsert(
            ids=[pattern["id"]],
            documents=[doc],
            metadatas=[meta],
        )
        if self._atlas:
            try:
                self._atlas.upsert([pattern["id"]], [doc], [meta])
            except Exception as exc:
                logger.warning("Atlas add_pattern failed — local KB still updated: %s", exc)
