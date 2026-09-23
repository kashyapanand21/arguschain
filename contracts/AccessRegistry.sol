// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Permissions} from "./libraries/Permissions.sol";
import {Principals} from "./libraries/Principals.sol";
import {ArgusIdentity} from "./ArgusIdentity.sol";
import {RoleRegistry} from "./RoleRegistry.sol";
import {AssetNFT} from "./AssetNFT.sol";
import {IAuthorizer} from "./interfaces/IAuthorizer.sol";

/// @title AccessRegistry
/// @notice Access Control Entries and the effective-permission resolver
///         (Section 5.4–5.6). A badge per (user, asset) cannot express
///         read-but-not-download, cannot expire and cannot deny — this
///         registry is the deliberate choice: tokens where tokens are the
///         right primitive (identity, roles, assets), a purpose-built table
///         where they are not.
contract AccessRegistry is AccessControl, IAuthorizer {
    bytes32 public constant ACL_WRITER_ROLE     = keccak256("ACL_WRITER_ROLE");     // relayer + admin, direct low-tier writes
    bytes32 public constant GRANT_EXECUTOR_ROLE = keccak256("GRANT_EXECUTOR_ROLE"); // GrantWorkflow
    bytes32 public constant ASSET_SEEDER_ROLE   = keccak256("ASSET_SEEDER_ROLE");   // AssetNFT, owner-default ACE on mint

    uint8 public constant CONFIDENTIAL = 2;

    struct Ace {
        uint32  allowMask;
        uint32  denyMask;
        uint64  notBefore;
        uint64  expiresAt;       // 0 = permanent; rejected for CONFIDENTIAL and above
        uint8   delegationDepth; // further re-shares allowed; 0 = terminal
        uint256 grantedBy;       // identityId of the proposer (type(uint256).max = system-seeded at mint)
        bytes32 justificationHash;
        uint64  grantedAt;
    }

    ArgusIdentity public immutable identity;
    RoleRegistry  public immutable roles;
    AssetNFT      public immutable assets;

    mapping(bytes32 => mapping(bytes32 => Ace)) internal aces;         // resourceId => principal => ACE
    mapping(bytes32 => bytes32[])               internal principalsAt; // enumerable for the UI

    event AceSet(
        bytes32 indexed resourceId, bytes32 indexed principal, uint32 allowMask, uint32 denyMask,
        uint64 notBefore, uint64 expiresAt, uint8 delegationDepth, uint256 grantedBy, bytes32 justificationHash
    );
    event AceRevoked(bytes32 indexed resourceId, bytes32 indexed principal, uint256 revokedBy);

    error Unauthorized();
    error RequiresWorkflow();
    error UnknownAsset();
    error JustificationRequired();
    error SelfGrantForbidden();
    error DelegationExceedsGrantor();
    error DelegationDepthExhausted();
    error NotActiveIdentity();

    constructor(address identity_, address roles_, address assets_, address admin) {
        identity = ArgusIdentity(identity_);
        roles = RoleRegistry(roles_);
        assets = AssetNFT(assets_);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ACL_WRITER_ROLE, admin);
    }

    // ------------------------------------------------------------------ writes

    /// @notice Direct ACE write. Refuses CONFIDENTIAL+ resources — those must
    ///         come through GrantWorkflow so a proposal with the required
    ///         approvals always exists first (Section 5.5, 5.7).
    function setAce(
        bytes32 resourceId, bytes32 principal, uint32 allowMask, uint32 denyMask,
        uint64 notBefore, uint64 expiresAt, uint8 delegationDepth,
        uint256 grantedBy, bytes32 justificationHash
    ) external {
                if (
            !hasRole(ACL_WRITER_ROLE, msg.sender) &&
            !hasRole(GRANT_EXECUTOR_ROLE, msg.sender) &&
            !hasRole(ASSET_SEEDER_ROLE, msg.sender) // AssetNFT, owner ACE handover on transfer
        ) revert Unauthorized();
        if (principal == Principals.identity(grantedBy)) revert SelfGrantForbidden();
        if (!assets.exists(uint256(resourceId))) revert UnknownAsset();
        if (assets.classificationOf(uint256(resourceId)) >= CONFIDENTIAL) revert RequiresWorkflow();
        _writeAce(resourceId, principal, allowMask, denyMask, notBefore, expiresAt, delegationDepth, grantedBy, justificationHash);
    }

    /// @notice Privileged path used by GrantWorkflow.execute() only.
    function executeGrant(
        bytes32 resourceId, bytes32 principal, uint32 allowMask, uint32 denyMask,
        uint64 notBefore, uint64 expiresAt, uint8 delegationDepth,
        uint256 grantedBy, bytes32 justificationHash
    ) external onlyRole(GRANT_EXECUTOR_ROLE) {
        _writeAce(resourceId, principal, allowMask, denyMask, notBefore, expiresAt, delegationDepth, grantedBy, justificationHash);
    }

    /// @notice Seeded by AssetNFT immediately after mint (Section 6.1). Called
    ///         twice: once for the owner (P_LIST|P_READ_META|P_READ|P_DOWNLOAD|
    ///         P_WRITE|P_SHARE — every content bit), and once for the ADMIN
    ///         role principal (P_LIST|P_ADMIN only — never a content bit, per
    ///         "the Admin who minted it receives none of the content bits").
    ///         Seeding the *role* principal rather than one admin's identity
    ///         means every Admin can manage the ACL on every asset, which is
    ///         also what makes a CONFIDENTIAL+ asset's very first ACE edit
    ///         possible at all: proposeGrant/proposeTransfer require the
    ///         proposer to already hold P_ADMIN, and without this seed no one
    ///         would.
    function seedAce(bytes32 resourceId, bytes32 principal, uint32 allowMask, bytes32 justificationHash)
        external
        onlyRole(ASSET_SEEDER_ROLE)
    {
        _writeAce(
            resourceId, principal, allowMask, 0, 0, 0, 2,
            type(uint256).max, // sentinel: system-seeded, not a proposer identity
            justificationHash
        );
    }

    /// @notice Re-share a strict subset of one's own permissions.
    /// @dev Enforces both halves of the delegation invariant: the delegated
    ///      mask is a subset of the delegator's own effective mask, and the
    ///      depth counter strictly decreases (INV-8 in the v3 sense; here it's
    ///      the delegation invariant, kept distinct from the role-rule INV-8).
    function delegate(bytes32 resourceId, bytes32 toPrincipal, uint32 allowMask, uint64 expiresAt, bytes32 justificationHash)
        external
    {
        uint256 me = identity.byController(msg.sender);
        if (me == 0 || !identity.isActive(me)) revert NotActiveIdentity();
        if (justificationHash == bytes32(0)) revert JustificationRequired();
        if (toPrincipal == Principals.identity(me)) revert SelfGrantForbidden();

        uint32 mine = effectivePermissionsForIdentity(resourceId, me);
        if (mine & Permissions.P_SHARE == 0) revert Unauthorized();
        if (allowMask & ~mine != 0) revert DelegationExceedsGrantor();

        uint8 depth = _delegationDepthOf(resourceId, Principals.identity(me));
        if (depth == 0) revert DelegationDepthExhausted();

        _writeAce(resourceId, toPrincipal, allowMask, 0, uint64(block.timestamp), expiresAt, depth - 1, me, justificationHash);
    }

    function revokeAce(bytes32 resourceId, bytes32 principal, uint256 revokedBy) external {
                if (
            !hasRole(ACL_WRITER_ROLE, msg.sender) &&
            !hasRole(GRANT_EXECUTOR_ROLE, msg.sender) &&
            !hasRole(ASSET_SEEDER_ROLE, msg.sender) // AssetNFT, owner ACE handover on transfer
        ) revert Unauthorized();
        delete aces[resourceId][principal];
        emit AceRevoked(resourceId, principal, revokedBy);
    }

    function _writeAce(
        bytes32 resourceId, bytes32 principal, uint32 allowMask, uint32 denyMask,
        uint64 notBefore, uint64 expiresAt, uint8 delegationDepth,
        uint256 grantedBy, bytes32 justificationHash
    ) private {
        if (justificationHash == bytes32(0)) revert JustificationRequired();
        bool firstWrite = aces[resourceId][principal].grantedAt == 0;
        aces[resourceId][principal] = Ace({
            allowMask: allowMask,
            denyMask: denyMask,
            notBefore: notBefore,
            expiresAt: expiresAt,
            delegationDepth: delegationDepth,
            grantedBy: grantedBy,
            justificationHash: justificationHash,
            grantedAt: uint64(block.timestamp)
        });
        if (firstWrite) principalsAt[resourceId].push(principal);
        emit AceSet(resourceId, principal, allowMask, denyMask, notBefore, expiresAt, delegationDepth, grantedBy, justificationHash);
    }

    // -------------------------------------------------------------- resolution

    function effectivePermissions(bytes32 resourceId, address account) public view returns (uint32) {
        uint256 idt = identity.byController(account);
        if (idt == 0) return 0;
        return effectivePermissionsForIdentity(resourceId, idt);
    }

    /// @notice The Figure 2 resolution algorithm. A view function — zero gas
    ///         via eth_call.
    function effectivePermissionsForIdentity(bytes32 resourceId, uint256 idt) public view returns (uint32 eff) {
        if (!identity.isActive(idt)) return 0;
        if (!assets.exists(uint256(resourceId))) return 0;

        bytes32[] memory subs = principalsOf(idt);
        uint32 allow;
        uint32 deny;
        for (uint256 i; i < subs.length; ++i) {
            Ace storage a = aces[resourceId][subs[i]];
            if (a.allowMask == 0 && a.denyMask == 0) continue;
            if (block.timestamp < a.notBefore) continue;
            if (a.expiresAt != 0 && block.timestamp >= a.expiresAt) continue;
            allow |= a.allowMask;
            deny  |= a.denyMask; // deny is a global override
        }
        eff = allow & ~deny;
        eff = _applyMandatoryAccessControl(eff, idt, resourceId);
        eff = _applyRoleRules(eff, idt);
    }

    /// @dev Clearance below classification: one level below is a greyed,
    ///      locked entry (name and classification only, P_LIST); anything
    ///      further is invisible, eff = 0 (Section 5.6 visibility rule).
    function _applyMandatoryAccessControl(uint32 eff, uint256 idt, bytes32 resourceId) private view returns (uint32) {
        uint8 clearance = identity.clearanceOf(idt);
        uint8 classification = assets.classificationOf(uint256(resourceId));
        if (clearance >= classification) return eff;
        if (classification == clearance + 1) return Permissions.P_LIST;
        return 0;
    }

    /// @dev Auditor sees metadata, ACL and history of every asset unconditionally
    ///      (Section 5.2). Auditor and Security Officer never hold content bits,
    ///      no matter what an ACE grants (INV-8: role rules run last and win).
    ///      Admin's P_LIST|P_ADMIN (seeded on every mint, Section 6.1) is
    ///      likewise restored after the MAC gate: administering an ACL never
    ///      exposes content, so an Admin's own clearance is not a reason to
    ///      block it — that's what makes "Admin grants but cannot read"
    ///      (Section 5.3) hold structurally rather than by convention. Unlike
    ///      Auditor/Security Officer, Admin is not barred from content bits
    ///      outright — the compliance table allows an Admin to read only if
    ///      someone else separately grants it — so this never strips them.
    function _applyRoleRules(uint32 eff, uint256 idt) private view returns (uint32) {
        address holder = identity.controllerOf(idt);
        bool isAuditor = roles.hasRoleToken(holder, roles.AUDITOR());
        bool isSecurityOfficer = roles.hasRoleToken(holder, roles.SECURITY_OFFICER());
        bool isAdmin = roles.hasRoleToken(holder, roles.ADMIN());

        if (isAuditor) {
            eff |= (Permissions.P_LIST | Permissions.P_READ_META | Permissions.P_AUDIT);
        }
        if (isAdmin) {
            eff |= (Permissions.P_LIST | Permissions.P_ADMIN);
        }
        if (isAuditor || isSecurityOfficer) {
            eff &= ~Permissions.CONTENT_BITS;
        }
        return eff;
    }

    /// @notice Collect every principal an identity resolves to: itself, plus
    ///         every role token it currently holds (Figure 2 step 2).
    function principalsOf(uint256 idt) public view returns (bytes32[] memory subs) {
        address holder = identity.controllerOf(idt);
        uint256 roleCount = 5; // ADMIN..SECURITY_OFFICER
        bytes32[] memory buf = new bytes32[](1 + roleCount);
        uint256 k;
        buf[k++] = Principals.identity(idt);
        for (uint256 r = 1; r <= roleCount; ++r) {
            if (roles.balanceOf(holder, r) > 0) buf[k++] = Principals.role(r);
        }
        subs = new bytes32[](k);
        for (uint256 i; i < k; ++i) subs[i] = buf[i];
    }

    // ------------------------------------------------------------------- reads

    function getAce(bytes32 resourceId, bytes32 principal) external view returns (Ace memory) {
        return aces[resourceId][principal];
    }

    function principalsOnResource(bytes32 resourceId) external view returns (bytes32[] memory) {
        return principalsAt[resourceId];
    }

    function _delegationDepthOf(bytes32 resourceId, bytes32 principal) private view returns (uint8) {
        Ace storage a = aces[resourceId][principal];
        return a.allowMask != 0 ? a.delegationDepth : 0;
    }
}
