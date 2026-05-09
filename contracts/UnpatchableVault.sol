// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ============================================================
// UnpatchableVault — DESIGNED TO DEFEAT THE AUTO-PATCH PIPELINE
//
// Six vulnerability classes that individually or in combination
// prevent the AI self-healing pipeline from autonomously patching.
//
// DO NOT DEPLOY TO MAINNET — FOR AI SECURITY RESEARCH ONLY.
// ============================================================

// ── ERC-3156 Flash Loan Interfaces (VULN-5) ─────────────────

interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

// ── Price Oracle Interface (VULN-3) ─────────────────────────

interface IOracle {
    function getPrice(address token) external view returns (uint256);
}

// ── Cross-Contract Reentrancy Interfaces (VULN-1) ────────────

interface IVaultNotifier {
    function notify(address user, uint256 amount) external;
}

interface IVaultUpdater {
    function update(address user, uint256 amount) external;
}

// ============================================================
// VULN-1: CROSS-CONTRACT REENTRANCY — VaultA → VaultB → VaultC → VaultA
//
// ⚠️  WHY THIS DEFEATS AUTO-PATCH:
//     nonReentrant on VaultA.withdraw() does NOT stop the attack.
//     Re-entry arrives from VaultC (a different call frame), bypassing
//     OpenZeppelin's ReentrancyGuard which only locks the current contract.
//     Slither still flags the cross-contract call chain after the patch.
//     Gate 1 (Slither clean) fails on every candidate → SLOW PATH.
// ============================================================

contract VaultA {
    mapping(address => uint256) public balances;
    IVaultNotifier public vaultB;
    address public owner;
    bool private _initialized;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function initialize(address _owner, address _vaultB) external {
        require(!_initialized, "already initialized");
        _initialized = true;
        owner = _owner;
        vaultB = IVaultNotifier(_vaultB);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // 🔴 VULN-1: CROSS-CONTRACT REENTRANCY
    // Withdraw triggers notification chain BEFORE zeroing balances.
    // VaultC.update() calls VaultA.deposit() back, inflating balances
    // while balances[msg.sender] is still unmodified.
    // Adding nonReentrant here does NOT block re-entry via VaultC.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");

        // 🔴 VULN-1: External call before state update — cross-contract path
        vaultB.notify(msg.sender, amount);

        // State zeroed AFTER the full VaultB→VaultC→VaultA triangle completes.
        // The attacker's balance was re-inflated during VaultC's callback,
        // so this subtract runs on stale data, allowing double withdrawal.
        balances[msg.sender] -= amount;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "ETH transfer failed");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}

contract VaultB {
    IVaultUpdater public vaultC;
    bool private _initialized;

    function initialize(address _vaultC) external {
        require(!_initialized);
        _initialized = true;
        vaultC = IVaultUpdater(_vaultC);
    }

    // Called by VaultA.withdraw() — triggers second leg of triangle
    function notify(address user, uint256 amount) external {
        vaultC.update(user, amount);
    }
}

contract VaultC {
    address payable public vaultA;
    bool private _initialized;

    function initialize(address _vaultA) external {
        require(!_initialized);
        _initialized = true;
        vaultA = payable(_vaultA);
    }

    // Called by VaultB.notify() — re-enters VaultA.deposit() BEFORE
    // VaultA has zeroed balances[user]. Completes the triangle.
    // VaultA.nonReentrant does NOT protect here — different call frame.
    function update(address user, uint256 amount) external {
        // A malicious VaultC would forward ETH from the attacker contract here.
        // In the demo the attacker primes this with { value: amount }.
        if (vaultA.balance >= amount) {
            (bool ok,) = vaultA.call{value: 0}(abi.encodeWithSignature("deposit()"));
            ok; // suppress warning
        }
    }
}


// ============================================================
// VULN-4: DELEGATECALL STORAGE COLLISION
//
// Storage slot 0 is used for THREE different variables across
// UnpatchableVault (owner: address), LogicContract (initialized: bool),
// and LibraryContract (emergencyMode: uint256).
//
// ⚠️  WHY THIS DEFEATS AUTO-PATCH:
//     Fixing requires rewriting storage layout across THREE contracts
//     deployed separately. The patch file (UnpatchableVault.sol) alone
//     cannot fix it — LogicContract.sol is out of scope.
//     cross_contract_flag = True on every finding → SLOW PATH always.
// ============================================================

contract LibraryContract {
    // 🔴 VULN-4: Slot 0 = emergencyMode — COLLIDES with UnpatchableVault.owner
    //            and LogicContract.initialized when used via delegatecall.
    uint256 public emergencyMode;

    function activateEmergency() external {
        emergencyMode = 1;  // Overwrites slot 0 of the calling contract
    }

    function deactivateEmergency() external {
        emergencyMode = 0;
    }
}

contract LogicContract {
    // 🔴 VULN-4: Slot 0 = initialized (bool) — COLLIDES with UnpatchableVault.owner (address)
    //            Writing initialized=true via delegatecall zeroes the lower 20 bytes
    //            of the owner slot, effectively setting owner = address(0).
    bool public initialized;
    address public libraryContract;

    // Slot 2 onwards used normally
    uint256 public version;

    function initialize() external {
        // Via delegatecall from UnpatchableVault: this sets slot 0 = 0x01
        // which OVERWRITES the lower byte of UnpatchableVault.owner → owner corruption
        initialized = true;
        version = 1;
    }

    function setLibrary(address lib) external {
        libraryContract = lib;
    }

    // 🔴 VULN-4: Nested delegatecall — all three contracts share slot 0 storage
    function delegateToLibrary(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = libraryContract.delegatecall(data);
        require(ok, "library delegatecall failed");
        return ret;
    }
}

// ============================================================
// Mock Oracle — returns 0 during "initialization" period (VULN-3)
// ============================================================

contract MockOracle {
    uint256 private _price;
    bool public ready;

    function setPrice(uint256 p) external { _price = p; ready = true; }

    // 🔴 VULN-3: Returns 0 when not yet initialized — triggers divide-by-zero
    //            in unchecked arithmetic block inside liquidate()
    function getPrice(address) external view returns (uint256) {
        return ready ? _price : 0;
    }
}


// ============================================================
// Main Contract — VULN-2, VULN-3, VULN-4, VULN-5, VULN-6
// ============================================================

contract UnpatchableVault {

    // ── Storage layout (slot positions are load-bearing for VULN-4) ──
    // Slot 0:  owner              ← COLLIDES with LogicContract.initialized
    address public owner;
    // Slot 1:  initialized
    bool public initialized;
    // Slot 2:  oracle
    address public oracle;
    // Slot 3:  governanceToken
    address public governanceToken;
    // Slot 4:  logicContract
    address public logicContract;
    // Slot 5:  emergencyTarget
    address public emergencyTarget;
    // Slot 6:  emergencyTimelockBlock
    uint256 public emergencyTimelockBlock;
    // Slot 7:  liquidationThreshold
    uint256 public liquidationThreshold;
    // Slot 8:  totalDeposits
    uint256 public totalDeposits;
    // Slot 9:  balances
    mapping(address => uint256) public balances;
    // Slot 10: governanceVotes (only 1 token needed — VULN-6)
    mapping(address => uint256) public governanceVotes;

    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event EmergencyTargetQueued(address target, uint256 executeBlock);
    event Liquidated(address indexed user, uint256 amount, uint256 price);
    event FlashLoan(address indexed borrower, uint256 amount);
    event SelfDestructed(address indexed caller);

    // ── 🔴 VULN-2: PUBLIC INITIALIZE — governance + reentrancy interaction ──
    //
    // ⚠️  WHY THIS DEFEATS AUTO-PATCH:
    //     Fixing initialize() access control breaks upgradeability pattern —
    //     proxies need to call initialize once. The LLM cannot distinguish
    //     "should be onlyOwner" from "should be initializer modifier".
    //     setEmergencyWithdraw() has a reentrancy vector inside a governance
    //     function. Fixing requires knowing if the verify() call is
    //     intentional business logic or removable. Semantic agent flags:
    //     AMBIGUOUS. Confidence drops. → SLOW PATH.
    function initialize(
        address _owner,
        address _oracle,
        address _token,
        address _logic
    ) public {
        // 🔴 VULN-2: No access control — anyone can call this and reinitialize
        //            if they front-run the legitimate deployer.
        require(!initialized, "already initialized");
        initialized  = true;
        owner        = _owner;
        oracle       = _oracle;
        governanceToken = _token;
        logicContract = _logic;
        liquidationThreshold = 80;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // 🔴 VULN-2: GOVERNANCE FUNCTION WITH REENTRANCY
    // External call to newTarget BEFORE emergencyTarget is stored.
    // newTarget.verify() can re-enter setEmergencyWithdraw() or any
    // other function. The timelock (2 blocks) gives false assurance —
    // the verify call happens immediately, before the lock takes effect.
    function setEmergencyWithdraw(address newTarget) external onlyOwner {
        // 🔴 VULN-2: External call before state update in governance function
        (bool ok,) = newTarget.call(abi.encodeWithSignature("verify()"));
        require(ok, "target verification failed");

        // Written AFTER the call — classic reentrancy in governance context
        emergencyTarget        = newTarget;
        emergencyTimelockBlock = block.number + 2;

        emit EmergencyTargetQueued(newTarget, emergencyTimelockBlock);
    }

    function executeEmergencyWithdraw(uint256 amount) external onlyOwner {
        require(emergencyTarget != address(0), "no target");
        require(block.number >= emergencyTimelockBlock, "timelock active");
        (bool ok,) = emergencyTarget.call{value: amount}("");
        require(ok, "emergency withdrawal failed");
    }

    // ── 🔴 VULN-3: ORACLE MANIPULATION + UNCHECKED ARITHMETIC ────────────
    //
    // ⚠️  WHY THIS DEFEATS AUTO-PATCH:
    //     1. Oracle can return 0 during initialization → division by zero
    //        inside unchecked block, or catastrophic underflow.
    //     2. block.timestamp manipulation shifts liquidationThreshold by ±9.
    //     3. Any fix that adds SafeMath or zero-checks rewrites the entire
    //        math block → source diff > 40% → flagged_for_review.
    //     4. Timestamp dependency is a separate vector the same patch must
    //        address simultaneously. All 3 candidates get flagged. → SLOW PATH.
    function liquidate(address user) external {
        // 🔴 VULN-3: Oracle returns 0 before ready — triggers divide-by-zero
        uint256 price = IOracle(oracle).getPrice(address(this));

        uint256 userBalance = balances[user];
        require(userBalance > 0, "nothing to liquidate");

        unchecked {
            // 🔴 VULN-3: If price == 0 → (userBalance * 0) / threshold = 0
            //            Then debt (totalDeposits / (userBalance + 1)) > 0
            //            → always liquidates, draining the vault.
            // 🔴 VULN-3: block.timestamp % 10 shifts threshold [0,9]
            //            Miners can manipulate this to trigger/prevent liquidation.
            uint256 adjustedThreshold = liquidationThreshold
                + (block.timestamp % 10);                    // timestamp vector

            uint256 collateralValue = (userBalance * price) / adjustedThreshold;
            uint256 debt            = totalDeposits / (userBalance + 1);

            if (collateralValue < debt) {
                balances[user]  = 0;
                totalDeposits  -= userBalance;

                (bool ok,) = msg.sender.call{value: userBalance}("");
                require(ok, "liquidation payout failed");

                emit Liquidated(user, userBalance, price);
            }
        }
    }

    // ── 🔴 VULN-4: DELEGATECALL STORAGE COLLISION ─────────────────────────
    //
    // ⚠️  WHY THIS DEFEATS AUTO-PATCH:
    //     UnpatchableVault.owner (slot 0, address, 20 bytes) collides with
    //     LogicContract.initialized (slot 0, bool, 1 byte) in delegatecall
    //     context. Calling upgradeLogic with initialize() calldata sets
    //     slot 0 = 0x01, zeroing 19 bytes of the owner address.
    //     Any patch that adds storage gaps to UnpatchableVault still
    //     breaks interaction with the separately deployed LogicContract.
    //     cross_contract_flag = True. Static + symbolic agents both flag.
    //     Patch would require coordinated update of both contracts. → SLOW PATH.
    function upgradeLogic(bytes calldata data) external onlyOwner {
        // 🔴 VULN-4: delegatecall to LogicContract — shares UnpatchableVault's storage
        //            LogicContract.initialize() writes slot 0 = 0x01 → corrupts owner
        //            LogicContract.delegateToLibrary() further delegates → triple collision
        (bool ok,) = logicContract.delegatecall(data);
        require(ok, "logic upgrade failed");
    }

    // ── 🔴 VULN-5: FLASH LOAN CALLBACK REENTRANCY (ERC-3156) ──────────────
    //
    // ⚠️  WHY THIS DEFEATS AUTO-PATCH:
    //     Patch Option A: Add nonReentrant → breaks ERC-3156 (callback is mandatory).
    //       Gate 3 (interface compliance) fails.
    //     Patch Option B: Remove onFlashLoan callback → function signature changes.
    //       Gate 3 fails (ABI mismatch).
    //     Patch Option C: Snapshot balance before, check snapshot after →
    //       source diff > 40% → flagged_for_review.
    //     All 3 candidates fail at least one gate. → SLOW PATH.
    function flashLoan(
        IERC3156FlashBorrower receiver,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        require(amount <= address(this).balance, "insufficient liquidity");

        uint256 ethBefore = address(this).balance;

        // Send loan to borrower
        (bool sent,) = address(receiver).call{value: amount}("");
        require(sent, "loan disbursement failed");

        emit FlashLoan(address(receiver), amount);

        // 🔴 VULN-5: ERC-3156 requires the callback — cannot remove it.
        //            During onFlashLoan, borrower calls deposit() to inflate
        //            address(this).balance before the repayment check below.
        bytes32 result = receiver.onFlashLoan(
            msg.sender, address(0), amount, 0, data
        );
        require(
            result == keccak256("ERC3156FlashBorrower.onFlashLoan"),
            "invalid flash loan callback"
        );

        // 🔴 VULN-5: Uses live address(this).balance, NOT ethBefore.
        //            Reentrant deposit() during callback inflates balance →
        //            repayment check passes even without repaying the loan.
        require(
            address(this).balance >= ethBefore,
            "flash loan not repaid"
        );

        return true;
    }

    // ── 🔴 VULN-6: SELFDESTRUCT + GOVERNANCE MANIPULATION ─────────────────
    //
    // ⚠️  WHY THIS DEFEATS AUTO-PATCH:
    //     Removing selfdestruct breaks the stated emergency recovery mechanism.
    //     The owner can be changed via voteForOwner() with only 1 governance
    //     token — an attacker acquires 1 token and takes over.
    //     Fixing governance requires redesigning the token voting system which
    //     spans multiple contracts (token contract is external, out of scope).
    //     Novel pattern — not in KB proven_patches partition.
    //     has_novel_patterns = True → confidence < 0.30 → SLOW PATH.

    // 1-token threshold for ownership change — trivially manipulable
    function voteForOwner(address candidate) external {
        // 🔴 VULN-6: Only 1 vote token required — attacker buys/borrows 1 token
        require(governanceVotes[msg.sender] >= 1, "need >= 1 governance vote");
        address old = owner;
        owner = candidate;
        emit OwnerChanged(old, candidate);
    }

    function grantVote(address voter, uint256 amount) external onlyOwner {
        governanceVotes[voter] += amount;
    }

    // 🔴 VULN-6: SELFDESTRUCT — kills implementation, proxy delegates to dead address
    //            After selfdestruct: proxy survives, delegatecall returns empty data,
    //            all vault functions silently succeed (no revert, no effect).
    //            Funds locked in the proxy forever.
    function emergencyDestruct() external onlyOwner {
        emit SelfDestructed(msg.sender);
        selfdestruct(payable(owner));
    }

    // ── Standard vault functions ────────────────────────────────────────────

    function deposit() external payable {
        require(msg.value > 0, "must send ETH");
        balances[msg.sender] += msg.value;
        totalDeposits        += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        totalDeposits        -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function setLiquidationThreshold(uint256 t) external onlyOwner {
        liquidationThreshold = t;
    }

    receive() external payable {
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
            totalDeposits        += msg.value;
        }
    }
}
