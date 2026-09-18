// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Permissions} from "./libraries/Permissions.sol";
import {Principals} from "./libraries/Principals.sol";
import {ArgusIdentity} from "./ArgusIdentity.sol";
import {DesignationRegistry} from "./DesignationRegistry.sol";
import {GroupRegistry} from "./GroupRegistry.sol";
import {ResourceRegistry} from "./ResourceRegistry.sol";
import {IAuthorizer} from "./interfaces/IAuthorizer.sol";

/// @title AccessRegistry
/// @notice Access Control Entries and the effective-permission resolver.
/// @dev An ERC-1155 badge per (user, file) cannot express read-but-not-download,
///      cannot expire and cannot deny. This registry is the deliberate choice:
///      tokens where tokens are the right primitive, a purpose-built ACL table
///      where they are not.
contract AccessRegistry is AccessControl, IAuthorizer {
    using Principals for uint256;

    bytes32 public constant ACL_WRITER_ROLE     = keccak256("ACL_WRITER_ROLE");     // relayer
    bytes32 public constant GRANT_EXECUTOR_ROLE = keccak256("GRANT_EXECUTOR_ROLE"); // GrantWorkflow

    uint8 public constant SECRET = 3;
    uint8 public constant MAX_DEPTH = 16;

    struct Ace {
        uint32  allowMask;
        uint32  denyMask;
        uint64  notBefore;
        uint64  expiresAt;      // 0 = permanent (discouraged for SECRET+)
        bool    inheritable;
        uint8   delegationDepth;
        bytes32 grantedBy;
        bytes32 justificationHash; // keccak of the mandatory written reason
        uint64  grantedAt;
    }

    ArgusIdentity       public immutable identity;
    DesignationRegistry public immutable designations;
    GroupRegistry       public immutable groups;
    ResourceRegistry    public immutable resources;

    mapping(bytes32 => mapping(bytes32 => Ace)) internal aces; // node => principal => ACE
    mapping(bytes32 => bytes32[]) internal principalsAt;       // node => enumerable for the UI

    event AceSet(
        bytes32 indexed node,
        bytes32 indexed principal,
        uint32 allowMask,
        uint32 denyMask,
        uint64 notBefore,
        uint64 expiresAt,
        bool inheritable,
        uint8 delegationDepth,
        bytes32 grantedBy,
        bytes32 justificationHash
    );
    event AceRevoked(bytes32 indexed node, bytes32 indexed principal, bytes32 revokedBy);

    error Unauthorized();
    error FourEyesRequired();
    error NoSuchNode();
    error JustificationRequired();
    error DelegationExceedsGrantor();
    error DelegationDepthExhausted();

    constructor(
        address admin,
        ArgusIdentity identity_,
        DesignationRegistry designations_,
        GroupRegistry groups_,
        ResourceRegistry resources_
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ACL_WRITER_ROLE, admin);
        identity     = identity_;
        designations = designations_;
        groups       = groups_;
        resources    = resources_;
    }

    // ------------------------------------------------------------------ writes

    /// @notice Direct ACE write. Refuses SECRET+ nodes - those must come through
    ///         GrantWorkflow so a two-approver proposal always exists.
    function setAce(
        bytes32 node,
        bytes32 principal,
        uint32  allowMask,
        uint32  denyMask,
        uint64  notBefore,
        uint64  expiresAt,
        bool    inheritable,
        uint8   delegationDepth,
        bytes32 grantedBy,
        bytes32 justificationHash
    ) external {
        if (!hasRole(ACL_WRITER_ROLE, msg.sender)) revert Unauthorized();
        if (!resources.exists(node)) revert NoSuchNode();
        if (justificationHash == bytes32(0)) revert JustificationRequired();
        if (resources.classificationOf(node) >= SECRET) revert FourEyesRequired();

        _writeAce(node, principal, allowMask, denyMask, notBefore, expiresAt,
                  inheritable, delegationDepth, grantedBy, justificationHash);
    }

    /// @notice Privileged path used by GrantWorkflow.execute() only.
    function executeGrant(
        bytes32 node,
        bytes32 principal,
        uint32  allowMask,
        uint32  denyMask,
        uint64  notBefore,
        uint64  expiresAt,
        bool    inheritable,
        uint8   delegationDepth,
        bytes32 grantedBy,
        bytes32 justificationHash
    ) external onlyRole(GRANT_EXECUTOR_ROLE) {
        _writeAce(node, principal, allowMask, denyMask, notBefore, expiresAt,
                  inheritable, delegationDepth, grantedBy, justificationHash);
    }

    /// @notice Re-share a strict subset of your own permissions.
    /// @dev Enforces both halves of the delegation invariant: the delegated mask
    ///      is a subset of the delegator's effective mask, and the depth counter
    ///      strictly decreases.
    function delegate(
        bytes32 node,
        bytes32 toPrincipal,
        uint32  allowMask,
        uint64  expiresAt,
        bytes32 justificationHash
    ) external {
        uint256 me = identity.byController(msg.sender);
        if (me == 0 || !identity.isActive(me)) revert Unauthorized();
        if (justificationHash == bytes32(0)) revert JustificationRequired();
        if (resources.classificationOf(node) >= SECRET) revert FourEyesRequired();

        uint32 mine = effectivePermissions(node, msg.sender);
        if (mine & Permissions.P_SHARE == 0) revert Unauthorized();
        if (allowMask & ~mine != 0) revert DelegationExceedsGrantor();

        uint8 depth = _delegationDepthOf(node, Principals.identity(me));
        if (depth == 0) revert DelegationDepthExhausted();

        _writeAce(node, toPrincipal, allowMask, 0, uint64(block.timestamp), expiresAt,
                  false, depth - 1, Principals.identity(me), justificationHash);
    }

    function revokeAce(bytes32 node, bytes32 principal, bytes32 revokedBy) external {
        if (!hasRole(ACL_WRITER_ROLE, msg.sender) && !hasRole(GRANT_EXECUTOR_ROLE, msg.sender)) {
            revert Unauthorized();
        }
        delete aces[node][principal];
        emit AceRevoked(node, principal, revokedBy);
    }

    function _writeAce(
        bytes32 node,
        bytes32 principal,
        uint32  allowMask,
        uint32  denyMask,
        uint64  notBefore,
        uint64  expiresAt,
        bool    inheritable,
        uint8   delegationDepth,
        bytes32 grantedBy,
        bytes32 justificationHash
    ) private {
        bool firstWrite = aces[node][principal].grantedAt == 0;
        aces[node][principal] = Ace({
            allowMask: allowMask,
            denyMask: denyMask,
            notBefore: notBefore,
            expiresAt: expiresAt,
            inheritable: inheritable,
            delegationDepth: delegationDepth,
            grantedBy: grantedBy,
            justificationHash: justificationHash,
            grantedAt: uint64(block.timestamp)
        });
        // grantedAt == 0 means this (node, principal) pair has never been written,
        // so it doubles as the "already enumerated" flag and saves a cold SSTORE
        if (firstWrite) principalsAt[node].push(principal);
        emit AceSet(node, principal, allowMask, denyMask, notBefore, expiresAt,
                    inheritable, delegationDepth, grantedBy, justificationHash);
    }

    // -------------------------------------------------------------- resolution

    /// @notice The resolution algorithm. A view function - zero gas via eth_call.
    function effectivePermissions(bytes32 node, address account)
        public
        view
        returns (uint32 eff)
    {
        uint256 idt = identity.byController(account);
        if (idt == 0 || !identity.isActive(idt)) return 0;
        return effectivePermissionsForIdentity(node, idt);
    }

    function effectivePermissionsForIdentity(bytes32 node, uint256 idt)
        public
        view
        returns (uint32 eff)
    {
        if (!identity.isActive(idt)) return 0;

        bytes32[] memory subs = principalsOf(idt);
        uint32 allow;
        uint32 deny;
        bytes32 cur = node;

        for (uint8 hop = 0; cur != bytes32(0) || hop == 0; ++hop) {
            if (hop >= MAX_DEPTH) break;
            ResourceRegistry.Node memory n = resources.get(cur);
            if (n.nodeType == ResourceRegistry.NodeType.NONE) break;

            for (uint256 i; i < subs.length; ++i) {
                Ace storage a = aces[cur][subs[i]];
                if (a.allowMask == 0 && a.denyMask == 0) continue;
                if (block.timestamp < a.notBefore) continue;
                if (a.expiresAt != 0 && block.timestamp >= a.expiresAt) continue;
                if (hop > 0 && !a.inheritable) continue; // non-inheritable ACEs above self

                allow |= a.allowMask;
                deny  |= a.denyMask; // deny is a global override
            }

            if (!n.inheritanceEnabled) break; // inheritance break stops the walk
            if (cur == bytes32(0)) break;     // reached root
            cur = n.parent;
        }

        eff = allow & ~deny;
        eff = _applyMandatoryAccessControl(eff, idt, node);
    }

    /// @dev Two gates, in order. Clearance failure leaves the audit trail visible
    ///      but nothing else; compartment failure leaves existence visible so a
    ///      user files a justified access request instead of a support ticket.
    function _applyMandatoryAccessControl(uint32 eff, uint256 idt, bytes32 node)
        private
        view
        returns (uint32)
    {
        uint8 clearance = identity.clearanceOf(idt);
        uint8 classification = resources.classificationOf(node);

        if (clearance < classification) {
            return eff & Permissions.P_AUDIT;
        }

        bytes32 compartment = resources.compartmentOf(node);
        if (!groups.hasCompartment(compartment, idt)) {
            // DEVIATION from spec Figure 2, deliberate: P_AUDIT survives the
            // need-to-know gate. Figure 2 strips it, which would contradict
            // section 3.1 - an Internal Auditor must see the trail of every
            // compartment without being read into any of them. P_AUDIT grants
            // history and effective-perms, never content, so this leaks nothing.
            return eff & (Permissions.METADATA_ONLY | Permissions.P_AUDIT);
        }
        return eff;
    }

    /// @notice Collect every principal an identity resolves to.
    function principalsOf(uint256 idt) public view returns (bytes32[] memory subs) {
        uint256[] memory desigs = designations.designationsOf(idt);
        uint256[] memory grps   = groups.groupsOf(idt);

        subs = new bytes32[](2 + desigs.length + grps.length);
        uint256 k;
        subs[k++] = Principals.identity(idt);
        for (uint256 i; i < desigs.length; ++i) subs[k++] = Principals.designation(desigs[i]);
        for (uint256 i; i < grps.length; ++i)   subs[k++] = Principals.group(grps[i]);
        subs[k++] = Principals.unit(identity.unitOf(idt));
    }

    // ------------------------------------------------------------------- reads

    function getAce(bytes32 node, bytes32 principal) external view returns (Ace memory) {
        return aces[node][principal];
    }

    function principalsOnNode(bytes32 node) external view returns (bytes32[] memory) {
        return principalsAt[node];
    }

    function _delegationDepthOf(bytes32 node, bytes32 principal) private view returns (uint8) {
        bytes32 cur = node;
        for (uint8 hop; hop < MAX_DEPTH; ++hop) {
            Ace storage a = aces[cur][principal];
            if (a.allowMask != 0 && (hop == 0 || a.inheritable)) return a.delegationDepth;
            ResourceRegistry.Node memory n = resources.get(cur);
            if (!n.inheritanceEnabled || cur == bytes32(0)) break;
            cur = n.parent;
        }
        return 0;
    }
}
