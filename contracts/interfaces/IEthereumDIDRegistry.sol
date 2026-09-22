// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEthereumDIDRegistry
/// @notice The slice of the ERC-1056 registry ArgusChain actually calls.
///         Deploy the canonical registry for the target network (or this
///         package's local reference copy, contracts/identity/EthereumDIDRegistry.sol)
///         and point ArgusIdentity at it — any ERC-1056-compliant deployment
///         is interchangeable here.
interface IEthereumDIDRegistry {
    function identityOwner(address identity) external view returns (address);
    function changeOwner(address identity, address newOwner) external;
    function validDelegate(address identity, bytes32 delegateType, address delegate) external view returns (bool);
    function addDelegate(address identity, bytes32 delegateType, address delegate, uint256 validity) external;
    function revokeDelegate(address identity, bytes32 delegateType, address delegate) external;
}
