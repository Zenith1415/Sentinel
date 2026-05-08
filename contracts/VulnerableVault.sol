// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title VulnerableVault
 * @notice INTENTIONALLY VULNERABLE — for AI self-healing demo only.
 *         DO NOT deploy to mainnet.
 *
 * Known vulnerabilities (AI agents will detect and patch these):
 *   [VULN-1] Reentrancy in withdraw() — state update happens AFTER external call
 *   [VULN-2] Missing access control on setOwner() — anyone can hijack ownership
 */
contract VulnerableVault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
    }

    // -------------------------------------------------------------------------
    // [VULN-1] REENTRANCY — external call before state update
    // Attack: malicious contract calls withdraw() recursively inside fallback()
    // Fix:    move `balances[msg.sender] = 0` BEFORE the call (CEI pattern)
    // -------------------------------------------------------------------------
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABLE: state not cleared before external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // BUG: balance updated after the call — attacker can re-enter above
        balances[msg.sender] -= amount;

        emit Withdrawn(msg.sender, amount);
    }

    function deposit() external payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // -------------------------------------------------------------------------
    // [VULN-2] MISSING ACCESS CONTROL — no onlyOwner modifier
    // Attack: any address can call setOwner() and take over the contract
    // Fix:    add `onlyOwner` modifier
    // -------------------------------------------------------------------------
    function setOwner(address newOwner) external {
        // VULNERABLE: missing onlyOwner — anyone can call this
        address old = owner();
        _transferOwnership(newOwner);
        emit OwnerChanged(old, newOwner);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // UUPS upgrade guard — only owner can authorize upgrades
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
