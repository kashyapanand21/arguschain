// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Permissions
/// @notice Permission bitmask used by every ACE in the system.
/// @dev P_READ and P_DOWNLOAD are deliberately separate: that split is what
///      allows "view watermarked in browser, no export" as a first-class grant.
library Permissions {
    uint32 internal constant P_LIST      = 1 << 0; // see the node exists in a listing
    uint32 internal constant P_READ_META = 1 << 1; // name, size, hash, classification, ACL
    uint32 internal constant P_READ      = 1 << 2; // decrypt content
    uint32 internal constant P_DOWNLOAD  = 1 << 3; // export raw, no watermark
    uint32 internal constant P_WRITE     = 1 << 4; // new version
    uint32 internal constant P_CREATE    = 1 << 5; // create children (folders only)
    uint32 internal constant P_DELETE    = 1 << 6; // deactivate
    uint32 internal constant P_SHARE     = 1 << 7; // delegate a subset of own perms
    uint32 internal constant P_ADMIN     = 1 << 8; // edit ACL, change classification
    uint32 internal constant P_AUDIT     = 1 << 9; // full history + effective perms of others

    uint32 internal constant ALL = 0x3FF;

    /// @notice Metadata-only residue used when a MAC gate blocks content access.
    uint32 internal constant METADATA_ONLY = P_LIST | P_READ_META;

    function has(uint32 mask, uint32 bit) internal pure returns (bool) {
        return mask & bit == bit;
    }
}
