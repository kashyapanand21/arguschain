// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Principals
/// @notice One bytes32 subject type for the two kinds of ACE grantee v4 ships
///         with: an individual identity, or a role token class. GROUP and UNIT
///         principals are Tier 3 (Appendix A) and arrive with the namehash
///         resource tree upgrade, not in this build.
library Principals {
    enum PrincipalType { NONE, IDENTITY, ROLE }

    function principalOf(PrincipalType t, uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(t), id));
    }

    function identity(uint256 id) internal pure returns (bytes32) {
        return principalOf(PrincipalType.IDENTITY, id);
    }

    function role(uint256 roleId) internal pure returns (bytes32) {
        return principalOf(PrincipalType.ROLE, roleId);
    }
}
