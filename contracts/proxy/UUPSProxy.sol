// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title UUPSProxy
 * @notice Thin ERC-1967 proxy shell. The implementation (logic contract)
 *         must be UUPSUpgradeable and authorize its own upgrades.
 */
contract UUPSProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data)
        ERC1967Proxy(implementation, data)
    {}
}
