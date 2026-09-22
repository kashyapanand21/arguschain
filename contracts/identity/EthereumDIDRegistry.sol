// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EthereumDIDRegistry
/// @notice A from-scratch, minimal ERC-1056 implementation for local and
///         test-network deployment. On a real network, deploy or reference
///         the canonical registry for that chain instead of this copy —
///         ArgusIdentity only calls identityOwner(), so any ERC-1056-compliant
///         deployment works interchangeably (Section 4.1). Every identity
///         defaults to owning itself: no transaction is needed until its
///         controlling key must rotate.
contract EthereumDIDRegistry {
    mapping(address => address) public owners;
    mapping(address => mapping(bytes32 => mapping(address => uint256))) public delegates;
    mapping(address => uint256) public changed;

    event DIDOwnerChanged(address indexed identity, address owner, uint256 previousChange);
    event DIDDelegateChanged(
        address indexed identity, bytes32 delegateType, address delegate, uint256 validTo, uint256 previousChange
    );

    error NotIdentityOwner();

    modifier onlyOwner(address identity) {
        if (msg.sender != identityOwner(identity)) revert NotIdentityOwner();
        _;
    }

    function identityOwner(address identity) public view returns (address) {
        address owner = owners[identity];
        return owner == address(0) ? identity : owner;
    }

    /// @notice Rotate the key that controls this DID. The old key stops
    ///         authenticating everywhere in ArgusChain immediately, because
    ///         every check reads this mapping live rather than a cached key.
    function changeOwner(address identity, address newOwner) public onlyOwner(identity) {
        owners[identity] = newOwner;
        emit DIDOwnerChanged(identity, newOwner, changed[identity]);
        changed[identity] = block.number;
    }

    function validDelegate(address identity, bytes32 delegateType, address delegate) public view returns (bool) {
        return delegates[identity][delegateType][delegate] > block.timestamp;
    }

    function addDelegate(address identity, bytes32 delegateType, address delegate, uint256 validity)
        public
        onlyOwner(identity)
    {
        uint256 validTo = block.timestamp + validity;
        delegates[identity][delegateType][delegate] = validTo;
        emit DIDDelegateChanged(identity, delegateType, delegate, validTo, changed[identity]);
        changed[identity] = block.number;
    }

    function revokeDelegate(address identity, bytes32 delegateType, address delegate) public onlyOwner(identity) {
        delegates[identity][delegateType][delegate] = block.timestamp;
        emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp, changed[identity]);
        changed[identity] = block.number;
    }
}
