// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAuthorizer
/// @notice The interface AssetNFT calls into AccessRegistry through, wired
///         post-deploy the same way v3's ResourceRegistry.setAuthorizer worked.
interface IAuthorizer {
    function effectivePermissions(bytes32 resourceId, address account) external view returns (uint32);
    function seedAce(bytes32 resourceId, bytes32 principal, uint32 allowMask, bytes32 justificationHash) external;
    function revokeAce(bytes32 resourceId, bytes32 principal, uint256 revokedBy) external;
}
