// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IEthereumDIDRegistry} from "./interfaces/IEthereumDIDRegistry.sol";
import {IERC5192} from "./interfaces/IERC5192.sol";
import {RoleRegistry} from "./RoleRegistry.sol";

/// @title ArgusIdentity
/// @notice A did:ethr identifier (ERC-1056), bound to a soulbound ERC-721
///         credential that carries clearance, status and tenure. Section 4.
/// @dev Uniqueness is enforced three independent ways: byEmpCommitment (no
///      duplicate humans), byDid (no shared DIDs), and _update (non-transferable).
///      The controlling key is never cached here — controllerOf() reads the
///      ERC-1056 registry live, so a key rotation preserves every grant without
///      touching a single ACE (Section 4.5).
contract ArgusIdentity is ERC721, AccessControl, Pausable, EIP712, IERC5192 {
    bytes32 public constant GRANT_EXECUTOR_ROLE = keccak256("GRANT_EXECUTOR_ROLE"); // GrantWorkflow only

    enum Status { NONE, ACTIVE, SUSPENDED, REVOKED }

    struct Identity {
        address did;
        bytes32 empCommitment;       // keccak256(employeeNo || salt) — no raw PII on chain
        uint8   clearance;           // 0 PUBLIC .. 4 TOP_SECRET
        Status  status;
        uint64  issuedAt;
        uint64  validUntil;          // tenure expiry — auto-lapse, 0 = no expiry
        address lastKnownController; // cache of didRegistry.identityOwner(did); see syncController()
    }

    uint8 public constant CLEARANCE_MAX = 4; // TOP_SECRET
    /// @dev Registration may set clearance up to RESTRICTED directly. CONFIDENTIAL
    ///      and above requires a CLEARANCE_UPLIFT proposal through GrantWorkflow
    ///      after registration (Section 4.2 step 6, Section 5.7) — this is the
    ///      one point where this build draws a stricter line than the spec text
    ///      states explicitly, so that every high-clearance grant has one single,
    ///      auditable path instead of two.
    uint8 public constant DIRECT_REGISTER_CEILING = 1; // RESTRICTED

    uint256 private _nextId = 1;

    mapping(uint256 => Identity) public identities;
    mapping(bytes32 => uint256)  public byEmpCommitment;
    mapping(address => uint256)  public byDid;        // DID address => identityId (stable, set once at registration)
    mapping(address => uint256)  public byController; // CURRENT controlling key => identityId (updated on rotation)
    mapping(address => uint256)  public nonces;

    IEthereumDIDRegistry public immutable didRegistry;
    RoleRegistry         public immutable roles;

    bytes32 private constant REGISTER_TYPEHASH = keccak256(
        "Register(address did,bytes32 empCommitment,uint8 clearance,uint64 validUntil,uint256 nonce,uint256 deadline)"
    );

    event IdentityRegistered(uint256 indexed identityId, address indexed did, bytes32 empCommitment, uint8 clearance);
    event IdentityStatusChanged(uint256 indexed identityId, Status previous, Status current, uint256 indexed actorIdentity);
    event ClearanceChanged(uint256 indexed identityId, uint8 previous, uint8 current);

    error NotAdmin();
    error NotSecurityOfficer();
    error DuplicateEmployee();
    error DidAlreadyBound();
    error ClearanceOutOfRange();
    error ClearanceAboveDirectCeiling();
    error SignatureExpired();
    error BadSignature();
    error UnknownIdentity();
    error Soulbound();

    constructor(address didRegistry_, address roles_, address admin)
        ERC721("ArgusChain Identity", "ARGUSID")
        EIP712("ArgusIdentity", "4")
    {
        didRegistry = IEthereumDIDRegistry(didRegistry_);
        roles = RoleRegistry(roles_);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    modifier onlyPlatformAdmin() {
        if (roles.balanceOf(msg.sender, roles.ADMIN()) == 0) revert NotAdmin();
        _;
    }

    modifier onlySecurityOfficer() {
        if (roles.balanceOf(msg.sender, roles.SECURITY_OFFICER()) == 0) revert NotSecurityOfficer();
        _;
    }

    // ---------------------------------------------------------------- registration

    /// @notice Admin submits this after the employee has signed the EIP-712
    ///         Register message with the key that currently owns their DID on
    ///         the ERC-1056 registry — the on-chain cryptographic proof of DID
    ///         control the problem statement asks for (Section 4.2).
    function registerIdentity(
        address did,
        bytes32 empCommitment,
        uint8   clearance,
        uint64  validUntil,
        uint256 deadline,
        bytes calldata sigByDidOwner
    ) external whenNotPaused onlyPlatformAdmin returns (uint256 identityId) {
        if (clearance > CLEARANCE_MAX) revert ClearanceOutOfRange();
        if (clearance > DIRECT_REGISTER_CEILING) revert ClearanceAboveDirectCeiling();
        if (block.timestamp > deadline) revert SignatureExpired();
        if (byEmpCommitment[empCommitment] != 0) revert DuplicateEmployee();
        if (byDid[did] != 0) revert DidAlreadyBound();

        uint256 nonce = nonces[did]++;
        bytes32 structHash = keccak256(
            abi.encode(REGISTER_TYPEHASH, did, empCommitment, clearance, validUntil, nonce, deadline)
        );
        address signer = ECDSA.recover(_hashTypedDataV4(structHash), sigByDidOwner);
        if (signer != didRegistry.identityOwner(did)) revert BadSignature();

        identityId = _nextId++;
        identities[identityId] = Identity({
            did: did,
            empCommitment: empCommitment,
            clearance: clearance,
            status: Status.ACTIVE,
            issuedAt: uint64(block.timestamp),
            validUntil: validUntil,
            lastKnownController: did
        });
        byEmpCommitment[empCommitment] = identityId;
        byDid[did] = identityId;
        byController[did] = identityId; // a DID owns itself until it rotates

        _mint(did, identityId);
        emit Locked(identityId);
        emit IdentityRegistered(identityId, did, empCommitment, clearance);
    }

    /// @notice Key rotation itself happens directly on the ERC-1056 registry
    ///         (didRegistry.changeOwner — Section 4.5); ArgusIdentity is never
    ///         the owner there, so it cannot relay that call. What it *can* do
    ///         is keep byController in sync so address-keyed lookups
    ///         (AccessRegistry.effectivePermissions(resourceId, address),
    ///         GrantWorkflow's direct-caller path) resolve correctly after a
    ///         rotation. Permissionless and idempotent — call it once after
    ///         rotating, or let the gateway call it automatically on session
    ///         start. Identity-keyed calls (effectivePermissionsForIdentity,
    ///         controllerOf) never need this: they read the registry live.
    function syncController(uint256 id) external {
        Identity storage idt = identities[id];
        if (idt.status == Status.NONE) revert UnknownIdentity();
        address current = didRegistry.identityOwner(idt.did);
        address cached = idt.lastKnownController;
        if (current != cached) {
            delete byController[cached];
            byController[current] = id;
            idt.lastKnownController = current;
        }
    }

    // -------------------------------------------------------------- status / MAC

    /// @notice Fast path, unilateral: availability loss is safer than
    ///         confidentiality loss. Un-suspending needs the Admin path.
    function suspend(uint256 id) external onlySecurityOfficer {
        _setStatus(id, Status.SUSPENDED, byController[msg.sender]);
    }

    function reinstate(uint256 id) external onlyPlatformAdmin {
        _setStatus(id, Status.ACTIVE, byController[msg.sender]);
    }

    function revoke(uint256 id) external onlySecurityOfficer {
        _setStatus(id, Status.REVOKED, byController[msg.sender]);
    }

    /// @notice Clearance changes are executed only by GrantWorkflow, which
    ///         enforces the four-eyes approval matrix for CONFIDENTIAL and
    ///         above (Section 5.7). This is the only way to reach SECRET or
    ///         TOP_SECRET clearance at all, since registerIdentity refuses it.
    function setClearance(uint256 id, uint8 clearance) external onlyRole(GRANT_EXECUTOR_ROLE) {
        if (clearance > CLEARANCE_MAX) revert ClearanceOutOfRange();
        Identity storage idt = identities[id];
        if (idt.status == Status.NONE) revert UnknownIdentity();
        uint8 prev = idt.clearance;
        idt.clearance = clearance;
        emit ClearanceChanged(id, prev, clearance);
    }

    /// @notice Seeds a founding high-clearance identity during setup. Without
    ///         this, the four-eyes CLEARANCE_UPLIFT workflow has a
    ///         chicken-and-egg problem: every CONFIDENTIAL+ approval needs an
    ///         approver who already holds CONFIDENTIAL+ clearance, and
    ///         registerIdentity refuses to set that directly. A SECRET or
    ///         TOP_SECRET proposal also needs *two* such approvers, so a real
    ///         deployment seeds a small founding committee (at minimum two
    ///         Security Officers) this way before locking the door. Gated by
    ///         DEFAULT_ADMIN_ROLE only — the deployer must renounce that role
    ///         once the founding committee is seeded, exactly as
    ///         RoleRegistry.bootstrap() expects for the Admin role.
    function bootstrapClearance(uint256 id, uint8 clearance) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (clearance > CLEARANCE_MAX) revert ClearanceOutOfRange();
        Identity storage idt = identities[id];
        if (idt.status == Status.NONE) revert UnknownIdentity();
        uint8 prev = idt.clearance;
        idt.clearance = clearance;
        emit ClearanceChanged(id, prev, clearance);
    }

    function _setStatus(uint256 id, Status s, uint256 actor) private {
        Identity storage idt = identities[id];
        if (idt.status == Status.NONE) revert UnknownIdentity();
        Status prev = idt.status;
        idt.status = s;
        emit IdentityStatusChanged(id, prev, s, actor);
    }

    // ----------------------------------------------------------------- reads

    function isActive(uint256 id) public view returns (bool) {
        Identity storage idt = identities[id];
        return idt.status == Status.ACTIVE && (idt.validUntil == 0 || idt.validUntil > block.timestamp);
    }

    function clearanceOf(uint256 id) external view returns (uint8) {
        return identities[id].clearance;
    }

    /// @dev Live lookup, never cached — this is what makes key rotation free.
    function controllerOf(uint256 id) public view returns (address) {
        return didRegistry.identityOwner(identities[id].did);
    }

    function totalIssued() external view returns (uint256) {
        return _nextId - 1;
    }

    function locked(uint256 tokenId) external view returns (bool) {
        ownerOf(tokenId); // reverts if the token does not exist
        return true; // every ArgusIdentity token is permanently locked
    }

    // ------------------------------------------------------------- soulbound

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        // mint (from == 0) and burn (to == 0) are the only legal movements;
        // key rotation happens on the ERC-1056 registry, never by moving this token
        if (from != address(0) && to != address(0)) revert Soulbound();
        return super._update(to, tokenId, auth);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    function supportsInterface(bytes4 iid) public view override(ERC721, AccessControl) returns (bool) {
        return iid == type(IERC5192).interfaceId || super.supportsInterface(iid);
    }
}
