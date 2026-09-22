// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ArgusIdentity} from "./ArgusIdentity.sol";
import {RoleRegistry} from "./RoleRegistry.sol";
import {AssetNFT} from "./AssetNFT.sol";
import {AccessRegistry} from "./AccessRegistry.sol";
import {Permissions} from "./libraries/Permissions.sol";
import {Principals} from "./libraries/Principals.sol";

/// @title GrantWorkflow
/// @notice Propose / approve / execute across every privileged action in the
///         system (Section 5.7): ACE grants, classified mint-and-allocate,
///         classified transfer, clearance uplifts, and new-Admin mints. One
///         unified path, so separation of duty is enforced identically no
///         matter which kind of grant is on the table — the account that
///         proposes access is never the account that approves it.
contract GrantWorkflow is AccessControl {
    bytes32 public constant WORKFLOW_ADMIN_ROLE = keccak256("WORKFLOW_ADMIN_ROLE");
    bytes32 public constant RELAYER_ROLE        = keccak256("RELAYER_ROLE");

    enum ProposalType { GRANT, MINT_AND_ALLOCATE, TRANSFER, CLEARANCE_UPLIFT, ADMIN_ROLE_MINT }

    uint8 public constant PUBLIC       = 0;
    uint8 public constant RESTRICTED   = 1;
    uint8 public constant CONFIDENTIAL = 2;
    uint8 public constant SECRET       = 3;
    uint8 public constant TOP_SECRET   = 4;

    struct Policy {
        uint8  approvalsRequired;
        bool   requireSecurityOfficer;
        bool   requireTopSecretApprovers; // TOP_SECRET only: every approver must hold TOP_SECRET clearance
        uint64 timelock;
        uint64 maxTtl;
    }

    struct Proposal {
        ProposalType kind;
        bytes32 resourceId;                // GRANT / TRANSFER: bytes32(tokenId)
        bytes32 principal;                 // GRANT only
        uint256 targetIdentity;            // TRANSFER / CLEARANCE_UPLIFT / MINT_AND_ALLOCATE
        address targetDid;                 // ADMIN_ROLE_MINT
        uint32  allowMask;
        uint32  denyMask;
        uint64  expiresAt;
        uint8   delegationDepth;
        uint8   tier;                      // classification or target clearance this proposal is judged against
        bytes32 contentHash;               // MINT_AND_ALLOCATE only
        bytes32 justificationHash;
        uint256 proposer;
        uint256[] approvers;
        uint64  readyAt;
        bool    executed;
        bool    rejected;
        bool    breakGlass;
    }

    uint64 public constant BREAK_GLASS_TTL = 4 hours;

    ArgusIdentity  public immutable identity;
    RoleRegistry   public immutable roles;
    AssetNFT       public immutable assets;
    AccessRegistry public immutable access;

    mapping(uint8 => Policy) public policyFor; // tier => policy

    uint256 private _nextPid = 1;
    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => mapping(uint256 => bool)) public hasApproved;

    event Proposed(uint256 indexed pid, ProposalType indexed kind, uint256 indexed proposer, uint8 tier, uint64 readyAt);
    event Approved(uint256 indexed pid, uint256 indexed approver, uint8 approvalsSoFar);
    event Rejected(uint256 indexed pid, uint256 indexed by);
    event Executed(uint256 indexed pid, ProposalType indexed kind);
    event BreakGlassUsed(uint256 indexed pid, uint256 indexed by);

    error NotActiveIdentity();
    error ProposerIsApprover();
    error AlreadyApproved();
    error InsufficientClearance();
    error SecurityOfficerRequired();
    error NotReady();
    error AlreadyFinalised();
    error TtlTooLong();
    error TtlRequired();
    error InsufficientApprovals();
    error NoAdminOnResource();
    error UnknownProposal();
    error NotSecurityOfficer();
    error SelfGrantForbidden();
    error UnknownAsset();
    error TierOutOfRange();

    constructor(address identity_, address roles_, address assets_, address access_, address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(WORKFLOW_ADMIN_ROLE, admin);
        identity = ArgusIdentity(identity_);
        roles = RoleRegistry(roles_);
        assets = AssetNFT(assets_);
        access = AccessRegistry(access_);

        //                         appr   SO      TS-only  timelock    maxTtl
        policyFor[PUBLIC]       = Policy(0, false, false, 0,        365 days);
        policyFor[RESTRICTED]   = Policy(0, false, false, 0,        365 days);
        policyFor[CONFIDENTIAL] = Policy(1, false, false, 0,        180 days);
        policyFor[SECRET]       = Policy(2, true,  false, 1 hours,  90 days);
        policyFor[TOP_SECRET]   = Policy(2, true,  true,  24 hours, 30 days);
    }

    function setPolicy(uint8 tier, Policy calldata p) external onlyRole(WORKFLOW_ADMIN_ROLE) {
        policyFor[tier] = p;
    }

    // -------------------------------------------------------------- GRANT

    function proposeGrant(
        uint256 resourceTokenId, bytes32 principal, uint32 allowMask, uint32 denyMask,
        uint64 expiresAt, uint8 delegationDepth, bytes32 justificationHash, uint256 proposerId
    ) external returns (uint256 pid) {
        uint256 proposer = _resolveActor(proposerId);
        if (!assets.exists(resourceTokenId)) revert UnknownAsset();
        bytes32 resourceId = bytes32(resourceTokenId);
        if (principal == Principals.identity(proposer)) revert SelfGrantForbidden();
        if (access.effectivePermissionsForIdentity(resourceId, proposer) & Permissions.P_ADMIN == 0) {
            revert NoAdminOnResource();
        }

        uint8 classification = assets.classificationOf(resourceTokenId);
        Policy memory p = policyFor[classification];
        if (classification >= CONFIDENTIAL && expiresAt == 0) revert TtlRequired();
        if (expiresAt != 0 && expiresAt > block.timestamp + p.maxTtl) revert TtlTooLong();

        pid = _nextPid++;
        Proposal storage pr = _proposals[pid];
        pr.kind = ProposalType.GRANT;
        pr.resourceId = resourceId;
        pr.principal = principal;
        pr.allowMask = allowMask;
        pr.denyMask = denyMask;
        pr.expiresAt = expiresAt;
        pr.delegationDepth = delegationDepth;
        pr.tier = classification;
        pr.justificationHash = justificationHash;
        pr.proposer = proposer;
        pr.readyAt = uint64(block.timestamp) + p.timelock;
        emit Proposed(pid, pr.kind, proposer, classification, pr.readyAt);
    }

    // ------------------------------------------------------- MINT_AND_ALLOCATE

    function proposeMint(
        uint256 toIdentity, bytes32 contentHash, uint8 classification, bytes32 justificationHash, uint256 proposerId
    ) external returns (uint256 pid) {
        uint256 proposer = _resolveActor(proposerId);
        if (roles.balanceOf(identity.controllerOf(proposer), roles.ADMIN()) == 0) revert NoAdminOnResource();
        if (classification > TOP_SECRET) revert TierOutOfRange();
        Policy memory p = policyFor[classification];

        pid = _nextPid++;
        Proposal storage pr = _proposals[pid];
        pr.kind = ProposalType.MINT_AND_ALLOCATE;
        pr.targetIdentity = toIdentity;
        pr.contentHash = contentHash;
        pr.tier = classification;
        pr.justificationHash = justificationHash;
        pr.proposer = proposer;
        pr.readyAt = uint64(block.timestamp) + p.timelock;
        emit Proposed(pid, pr.kind, proposer, classification, pr.readyAt);
    }

    // ------------------------------------------------------------- TRANSFER

    function proposeTransfer(
        uint256 tokenId, uint256 toIdentity, bytes32 justificationHash, uint256 proposerId
    ) external returns (uint256 pid) {
        uint256 proposer = _resolveActor(proposerId);
        if (!assets.exists(tokenId)) revert UnknownAsset();
        bytes32 resourceId = bytes32(tokenId);
        if (access.effectivePermissionsForIdentity(resourceId, proposer) & Permissions.P_ADMIN == 0) {
            revert NoAdminOnResource();
        }
        uint8 classification = assets.classificationOf(tokenId);
        Policy memory p = policyFor[classification];

        pid = _nextPid++;
        Proposal storage pr = _proposals[pid];
        pr.kind = ProposalType.TRANSFER;
        pr.resourceId = resourceId;
        pr.targetIdentity = toIdentity;
        pr.tier = classification;
        pr.justificationHash = justificationHash;
        pr.proposer = proposer;
        pr.readyAt = uint64(block.timestamp) + p.timelock;
        emit Proposed(pid, pr.kind, proposer, classification, pr.readyAt);
    }

    // ------------------------------------------------------- CLEARANCE_UPLIFT

    function proposeClearanceUplift(
        uint256 targetIdentity, uint8 newClearance, bytes32 justificationHash, uint256 proposerId
    ) external returns (uint256 pid) {
        uint256 proposer = _resolveActor(proposerId);
        if (roles.balanceOf(identity.controllerOf(proposer), roles.ADMIN()) == 0) revert NoAdminOnResource();
        if (newClearance > TOP_SECRET) revert TierOutOfRange();
        Policy memory p = policyFor[newClearance];

        pid = _nextPid++;
        Proposal storage pr = _proposals[pid];
        pr.kind = ProposalType.CLEARANCE_UPLIFT;
        pr.targetIdentity = targetIdentity;
        pr.tier = newClearance;
        pr.justificationHash = justificationHash;
        pr.proposer = proposer;
        pr.readyAt = uint64(block.timestamp) + p.timelock;
        emit Proposed(pid, pr.kind, proposer, newClearance, pr.readyAt);
    }

    // ------------------------------------------------------- ADMIN_ROLE_MINT

    /// @notice Minting a new Admin is judged at the TOP_SECRET tier — the
    ///         most powerful role in the system gets the strictest gate.
    function proposeAdminGrant(address toDid, bytes32 justificationHash, uint256 proposerId) external returns (uint256 pid) {
        uint256 proposer = _resolveActor(proposerId);
        if (roles.balanceOf(identity.controllerOf(proposer), roles.ADMIN()) == 0) revert NoAdminOnResource();
        Policy memory p = policyFor[TOP_SECRET];

        pid = _nextPid++;
        Proposal storage pr = _proposals[pid];
        pr.kind = ProposalType.ADMIN_ROLE_MINT;
        pr.targetDid = toDid;
        pr.tier = TOP_SECRET;
        pr.justificationHash = justificationHash;
        pr.proposer = proposer;
        pr.readyAt = uint64(block.timestamp) + p.timelock;
        emit Proposed(pid, pr.kind, proposer, TOP_SECRET, pr.readyAt);
    }

    // -------------------------------------------------------------- lifecycle

    function approve(uint256 pid, uint256 approverId) external {
        Proposal storage pr = _live(pid);
        uint256 approver = _resolveActor(approverId);
        Policy memory p = policyFor[pr.tier];

        if (approver == pr.proposer) revert ProposerIsApprover();
        if (hasApproved[pid][approver]) revert AlreadyApproved();
        if (identity.clearanceOf(approver) < pr.tier) revert InsufficientClearance();

        hasApproved[pid][approver] = true;
        pr.approvers.push(approver);

        // Security-Officer and TOP_SECRET-clearance requirements are checked
        // once enough approvals exist, so approvers may arrive in any order.
        if (pr.approvers.length >= p.approvalsRequired) {
            if (p.requireSecurityOfficer) {
                bool foundSO;
                for (uint256 i; i < pr.approvers.length; ++i) {
                    if (roles.hasRoleToken(identity.controllerOf(pr.approvers[i]), roles.SECURITY_OFFICER())) {
                        foundSO = true;
                        break;
                    }
                }
                if (!foundSO) revert SecurityOfficerRequired();
            }
            if (p.requireTopSecretApprovers) {
                for (uint256 i; i < pr.approvers.length; ++i) {
                    if (identity.clearanceOf(pr.approvers[i]) < TOP_SECRET) revert InsufficientClearance();
                }
            }
        }
        emit Approved(pid, approver, uint8(pr.approvers.length));
    }

    function reject(uint256 pid, uint256 byId) external {
        Proposal storage pr = _live(pid);
        uint256 by = _resolveActor(byId);
        pr.rejected = true;
        emit Rejected(pid, by);
    }

    /// @notice Anyone may execute once the approvals and timelock are satisfied.
    function execute(uint256 pid) external {
        Proposal storage pr = _live(pid);
        Policy memory p = policyFor[pr.tier];

        if (pr.approvers.length < p.approvalsRequired) revert InsufficientApprovals();
        if (block.timestamp < pr.readyAt) revert NotReady();

        pr.executed = true;
        _dispatch(pr);
        emit Executed(pid, pr.kind);
    }

    function _dispatch(Proposal storage pr) private {
        if (pr.kind == ProposalType.GRANT) {
            access.executeGrant(
                pr.resourceId, pr.principal, pr.allowMask, pr.denyMask,
                uint64(block.timestamp), pr.expiresAt, pr.delegationDepth,
                pr.proposer, pr.justificationHash
            );
        } else if (pr.kind == ProposalType.MINT_AND_ALLOCATE) {
            assets.executeMint(pr.targetIdentity, pr.contentHash, pr.tier, pr.justificationHash);
        } else if (pr.kind == ProposalType.TRANSFER) {
            assets.executeTransfer(uint256(pr.resourceId), pr.targetIdentity, pr.justificationHash);
        } else if (pr.kind == ProposalType.CLEARANCE_UPLIFT) {
            identity.setClearance(pr.targetIdentity, pr.tier);
        } else {
            roles.executeAdminGrant(pr.targetDid);
        }
    }

    /// @notice Emergency bypass of the timelock. Callable directly by a
    ///         Security Officer's own wallet (or via the relayer on their
    ///         behalf, after step-up), permanently flagged on the proposal,
    ///         and — for GRANT proposals — caps the grant's own expiry at
    ///         four hours from now so it cannot outlive the emergency that
    ///         justified it. A P1 alert is the off-chain half of this control.
    function breakGlass(uint256 pid, uint256 byId) external {
        Proposal storage pr = _live(pid);
        uint256 by = _resolveActor(byId);
        if (!roles.hasRoleToken(identity.controllerOf(by), roles.SECURITY_OFFICER())) revert NotSecurityOfficer();

        pr.breakGlass = true;
        pr.readyAt = uint64(block.timestamp);
        if (pr.kind == ProposalType.GRANT) {
            uint64 cap = uint64(block.timestamp) + BREAK_GLASS_TTL;
            if (pr.expiresAt == 0 || pr.expiresAt > cap) pr.expiresAt = cap;
        }
        emit BreakGlassUsed(pid, by);
    }

    // ------------------------------------------------------------------ reads

    function getProposal(uint256 pid) external view returns (Proposal memory) {
        return _proposals[pid];
    }

    function approversOf(uint256 pid) external view returns (uint256[] memory) {
        return _proposals[pid].approvers;
    }

    function totalProposals() external view returns (uint256) {
        return _nextPid - 1;
    }

    function _live(uint256 pid) private view returns (Proposal storage pr) {
        pr = _proposals[pid];
        if (pr.proposer == 0) revert UnknownProposal();
        if (pr.executed || pr.rejected) revert AlreadyFinalised();
    }

    /// @dev Direct callers act as themselves; the relayer may act on behalf of
    ///      a named identity after the gateway has verified a step-up signature.
    function _resolveActor(uint256 claimed) private view returns (uint256 id) {
        if (hasRole(RELAYER_ROLE, msg.sender)) {
            id = claimed;
        } else {
            id = identity.byController(msg.sender);
        }
        if (id == 0 || !identity.isActive(id)) revert NotActiveIdentity();
    }
}
