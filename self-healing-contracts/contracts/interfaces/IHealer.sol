// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title IHealer
 * @notice Interface that every healed implementation must satisfy so the
 *         AI deployer can verify the upgrade before submitting on-chain.
 */
interface IHealer {
    /// @notice Returns the semver version string of this implementation.
    function version() external pure returns (string memory);

    /// @notice Returns true if all known vulnerability patches are applied.
    function isHealed() external pure returns (bool);
}
