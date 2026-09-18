// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Principals
/// @notice One bytes32 subject type for four kinds of grantee.
/// @dev This is the abstraction that lets a single ACL table hold per-individual
///      grants *and* role grants without branching anywhere in the resolver.
library Principals {
    enum PrincipalType { NONE, IDENTITY, DESIGNATION, GROUP, UNIT }

    function principalOf(PrincipalType t, uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(t), id));
    }

    function identity(uint256 id) internal pure returns (bytes32) {
        return principalOf(PrincipalType.IDENTITY, id);
    }

    function designation(uint256 id) internal pure returns (bytes32) {
        return principalOf(PrincipalType.DESIGNATION, id);
    }

    function group(uint256 id) internal pure returns (bytes32) {
        return principalOf(PrincipalType.GROUP, id);
    }

    function unit(bytes32 unitId) internal pure returns (bytes32) {
        return principalOf(PrincipalType.UNIT, uint256(unitId));
    }
}
