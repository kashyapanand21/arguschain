// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ArgusIdentity} from "./ArgusIdentity.sol";
import {DesignationRegistry} from "./DesignationRegistry.sol";
import {ResourceRegistry} from "./ResourceRegistry.sol";
import {AccessRegistry} from "./AccessRegistry.sol";
import {Permissions} from "./libraries/Permissions.sol";
import {Principals} from "./libraries/Principals.sol";

/// @title GrantWorkflow
/// @notice Propose / approve / execute with separation of duty and timelocks.
/// @dev Separation of duty is the control BEL would reject the system without:
///      the account that grants access is never the account that reads content,
///      and proposer != approver is enforced on-chain, not in the UI.
contract GrantWorkflow is AccessControl {
    bytes32 public constant WORKFLOW_ADMIN_ROLE = keccak256("WORKFLOW_ADMIN_ROLE");
    bytes32 public constant RELAYER_ROLE        = keccak256("RELAYER_ROLE");

    struct Policy {
        uint8  approvalsRequired;
        uint8  minApproverGrade;
        bool   requireSecurityOfficer;
        bool   requireDifferentUnit;
        uint64 timelock;
        uint64 maxTtl;
    }

    struct Proposal {
        bytes32 node;
        bytes32 principal;
        uint32  allowMask;
        uint32  denyMask;
        uint64  expiresAt;
        bool    inheritable;
        uint8   delegationDepth;
        bytes32 justificationHash;
        uint256 proposer;
        uint256[] approvers;
        uint64  readyAt;
        uint8   classification;
        bool    executed;
        bool    rejected;
        bool    breakGlass;
    }

    uint64 public constant BREAK_GLASS_TTL = 4 hours;

    ArgusIdentity       public immutable identity;
    DesignationRegistry public immutable designations;
    ResourceRegistry    public immutable resources;
    AccessRegistry      public immutable access;

    uint256 public securityOfficerDesignation = 22;
    mapping(uint8 => Policy) public policyFor; // classification => policy

    uint256 private _nextPid = 1;
    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => mapping(uint256 => bool)) public hasApproved;

    event Proposed(uint256 indexed pid, bytes32 indexed node, bytes32 indexed principal, uint256 proposer, uint8 classification, uint64 readyAt);
    event Approved(uint256 indexed pid, uint256 indexed approver, uint8 approvalsSoFar);
    event Rejected(uint256 indexed pid, uint256 indexed by);
    event Executed(uint256 indexed pid, bytes32 indexed node, bytes32 indexed principal);
    event BreakGlassUsed(uint256 indexed pid, uint256 indexed by, bytes32 node);

    error NotActiveIdentity();
    error ProposerIsApprover();
    error AlreadyApproved();
    error InsufficientGrade();
    error SecurityOfficerRequired();
    error SameOrgUnit();
    error NotReady();
    error AlreadyFinalised();
    error TtlTooLong();
    error TtlRequired();
    error InsufficientApprovals();
    error NoAdminOnNode();
    error UnknownProposal();

    constructor(
        address admin,
        ArgusIdentity identity_,
        DesignationRegistry designations_,
        ResourceRegistry resources_,
        AccessRegistry access_
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(WORKFLOW_ADMIN_ROLE, admin);
        identity     = identity_;
        designations = designations_;
        resources    = resources_;
        access       = access_;

        //                         appr grade  SO     diffUnit timelock   maxTtl
        policyFor[0] = Policy(0,  0, false, false, 0,        365 days);
        policyFor[1] = Policy(0,  0, false, false, 0,        365 days);
        policyFor[2] = Policy(1,  4, false, false, 0,        180 days);
        policyFor[3] = Policy(2,  0, true,  true,  1 hours,  90 days);
        policyFor[4] = Policy(2,  8, true,  true,  24 hours, 30 days);
    }

    function setPolicy(uint8 classification, Policy calldata p) external onlyRole(WORKFLOW_ADMIN_ROLE) {
        policyFor[classification] = p;
    }

    function setSecurityOfficerDesignation(uint256 d) external onlyRole(WORKFLOW_ADMIN_ROLE) {
        securityOfficerDesignation = d;
    }

    // -------------------------------------------------------------- lifecycle

    function propose(
        bytes32 node,
        bytes32 principal,
        uint32  allowMask,
        uint32  denyMask,
        uint64  expiresAt,
        bool    inheritable,
        uint8   delegationDepth,
        bytes32 justificationHash,
        uint256 proposerId
    ) external returns (uint256 pid) {
        uint256 proposer = _resolveActor(proposerId);
        uint8 classification = resources.classificationOf(node);
        Policy memory p = policyFor[classification];

        // the proposer must actually administer the node
        if (access.effectivePermissionsForIdentity(node, proposer) & Permissions.P_ADMIN == 0) {
            revert NoAdminOnNode();
        }
        if (classification >= 3 && expiresAt == 0) revert TtlRequired();
        if (expiresAt != 0 && expiresAt > block.timestamp + p.maxTtl) revert TtlTooLong();

        pid = _nextPid++;
        Proposal storage pr = _proposals[pid];
        pr.node = node;
        pr.principal = principal;
        pr.allowMask = allowMask;
        pr.denyMask = denyMask;
        pr.expiresAt = expiresAt;
        pr.inheritable = inheritable;
        pr.delegationDepth = delegationDepth;
        pr.justificationHash = justificationHash;
        pr.proposer = proposer;
        pr.classification = classification;
        pr.readyAt = uint64(block.timestamp) + p.timelock;

        emit Proposed(pid, node, principal, proposer, classification, pr.readyAt);
    }

    function approve(uint256 pid, uint256 approverId) external {
        Proposal storage pr = _live(pid);
        uint256 approver = _resolveActor(approverId);
        Policy memory p = policyFor[pr.classification];

        if (approver == pr.proposer) revert ProposerIsApprover();
        if (hasApproved[pid][approver]) revert AlreadyApproved();
        if (p.minApproverGrade > 0 && designations.gradeOf(approver) < p.minApproverGrade) {
            revert InsufficientGrade();
        }
        if (p.requireDifferentUnit && identity.unitOf(approver) == identity.unitOf(pr.proposer)) {
            revert SameOrgUnit();
        }

        hasApproved[pid][approver] = true;
        pr.approvers.push(approver);

        // at least one approver must be a Security Officer, checked on the last
        // approval so approvers may arrive in any order
        if (pr.approvers.length >= p.approvalsRequired && p.requireSecurityOfficer) {
            bool found;
            for (uint256 i; i < pr.approvers.length; ++i) {
                if (designations.hasDesignation(pr.approvers[i], securityOfficerDesignation)) {
                    found = true;
                    break;
                }
            }
            if (!found) revert SecurityOfficerRequired();
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
        Policy memory p = policyFor[pr.classification];

        if (pr.approvers.length < p.approvalsRequired) revert InsufficientApprovals();
        if (block.timestamp < pr.readyAt) revert NotReady();

        pr.executed = true;
        access.executeGrant(
            pr.node,
            pr.principal,
            pr.allowMask,
            pr.denyMask,
            uint64(block.timestamp),
            pr.expiresAt,
            pr.inheritable,
            pr.delegationDepth,
            Principals.identity(pr.proposer),
            pr.justificationHash
        );
        emit Executed(pid, pr.node, pr.principal);
    }

    /// @notice Emergency bypass of the timelock. Auto-expires in 4 hours, is
    ///         permanently flagged, and fires a P1 alert off-chain.
    function breakGlass(uint256 pid, uint256 byId) external onlyRole(WORKFLOW_ADMIN_ROLE) {
        Proposal storage pr = _live(pid);
        uint256 by = _resolveActor(byId);
        if (!designations.hasDesignation(by, securityOfficerDesignation)) {
            revert SecurityOfficerRequired();
        }
        pr.breakGlass = true;
        pr.readyAt = uint64(block.timestamp);
        pr.expiresAt = uint64(block.timestamp) + BREAK_GLASS_TTL;
        emit BreakGlassUsed(pid, by, pr.node);
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

    /// @dev Direct callers act as themselves; the relayer may act on behalf of a
    ///      named identity after the gateway has verified a step-up signature.
    function _resolveActor(uint256 claimed) private view returns (uint256 id) {
        if (hasRole(RELAYER_ROLE, msg.sender)) {
            id = claimed;
        } else {
            id = identity.byController(msg.sender);
        }
        if (id == 0 || !identity.isActive(id)) revert NotActiveIdentity();
    }
}
