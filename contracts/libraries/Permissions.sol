// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Permissions
/// @notice The 8-bit permission mask used by every ACE in AccessRegistry.
/// @dev P_READ and P_DOWNLOAD are deliberately separate: that split is what
///      lets "view watermarked in browser, no export" exist as a first-class
///      grant. Matches spec Section 5.4 exactly (v4 dropped v3's P_CREATE and
///      P_DELETE — assets are minted/deactivated through Admin and workflow
///      paths, not through a generic ACE bit).
library Permissions {
    uint32 internal constant P_LIST      = 1 << 0; // appears in a listing
    uint32 internal constant P_READ_META = 1 << 1; // size, hash, version, owner, ACL, history
    uint32 internal constant P_READ      = 1 << 2; // view decrypted content, rendered, no export
    uint32 internal constant P_DOWNLOAD  = 1 << 3; // export the raw file
    uint32 internal constant P_WRITE     = 1 << 4; // upload a new version
    uint32 internal constant P_SHARE     = 1 << 5; // delegate a subset of own permissions
    uint32 internal constant P_ADMIN     = 1 << 6; // edit the ACL, propose classification/transfer changes
    uint32 internal constant P_AUDIT     = 1 << 7; // full history + effective permissions of others

    uint32 internal constant CONTENT_BITS  = P_READ | P_DOWNLOAD | P_WRITE;
    uint32 internal constant METADATA_BITS = P_LIST | P_READ_META;
    uint32 internal constant ALL           = 0xFF;

    function has(uint32 mask, uint32 bit) internal pure returns (bool) {
        return mask & bit == bit;
    }
}
