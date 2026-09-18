// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title ArgusIdentity
/// @notice One human, one identity, many keys. Soulbound ERC-721.
/// @dev Uniqueness is enforced on-chain in three independent ways:
///      1. byEmpCommitment  - no duplicate humans
///      2. byController     - no shared/reused wallets
///      3. _update override - non-transferable
contract ArgusIdentity is ERC721, AccessControl, Pausable {
    using ECDSA for bytes32;

    bytes32 public constant IDENTITY_ADMIN_ROLE   = keccak256("IDENTITY_ADMIN_ROLE");
    bytes32 public constant SECURITY_OFFICER_ROLE = keccak256("SECURITY_OFFICER_ROLE");

    enum Status { NONE, PENDING, ACTIVE, SUSPENDED, REVOKED }

    struct Identity {
        bytes32 empCommitment; // keccak256(employeeNo || salt) - never raw PII
        bytes32 unitId;
        bytes32 divisionId;
        uint8   clearance;     // 0 PUBLIC .. 4 TOP_SECRET
        Status  status;
        uint64  issuedAt;
        uint64  validUntil;    // tenure expiry - auto-lapse
        bytes32 x25519Pub;     // registered encryption pubkey
        address controller;    // current signing key
    }

    uint256 private _nextId = 1;

    mapping(uint256 => Identity) public identities;
    mapping(bytes32 => uint256)  public byEmpCommitment;
    mapping(address => uint256)  public byController;
    mapping(uint256 => uint256)  public rotationNonce;

    event IdentityIssued(uint256 indexed id, bytes32 indexed empCommitment, address controller, uint8 clearance);
    event ControllerRotated(uint256 indexed id, address indexed oldKey, address indexed newKey);
    event StatusChanged(uint256 indexed id, Status previous, Status current);
    event ClearanceChanged(uint256 indexed id, uint8 previous, uint8 current);
    event EncryptionKeyRegistered(uint256 indexed id, bytes32 x25519Pub);

    error DuplicateEmployee();
    error WalletAlreadyBound();
    error Soulbound();
    error UnknownIdentity();
    error BadRotationSignature();
    error ClearanceOutOfRange();

    constructor(address admin) ERC721("ArgusChain Identity", "ARGUSID") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(IDENTITY_ADMIN_ROLE, admin);
    }

    // ---------------------------------------------------------------- issuance

    function issue(
        bytes32 empCommitment,
        address controller,
        bytes32 unitId,
        bytes32 divisionId,
        uint8   clearance,
        uint64  validUntil
    ) external onlyRole(IDENTITY_ADMIN_ROLE) whenNotPaused returns (uint256 id) {
        if (clearance > 4) revert ClearanceOutOfRange();
        if (byEmpCommitment[empCommitment] != 0) revert DuplicateEmployee();
        if (byController[controller] != 0) revert WalletAlreadyBound();

        id = _nextId++;
        identities[id] = Identity({
            empCommitment: empCommitment,
            unitId: unitId,
            divisionId: divisionId,
            clearance: clearance,
            status: Status.ACTIVE,
            issuedAt: uint64(block.timestamp),
            validUntil: validUntil,
            x25519Pub: bytes32(0),
            controller: controller
        });
        byEmpCommitment[empCommitment] = id;
        byController[controller] = id;

        _mint(controller, id);
        emit IdentityIssued(id, empCommitment, controller, clearance);
    }

    // ------------------------------------------------------------ key handling

    /// @notice Rotate the signing key without touching a single ACE.
    /// @dev The new key proves possession by signing over
    ///      (chainid, this, id, newKey, nonce). Grants reference the identityId,
    ///      so rotation is a one-mapping update - compare to re-minting every
    ///      badge a user held.
    function rotateController(uint256 id, address newKey, bytes calldata sigFromNewKey)
        external
        whenNotPaused
    {
        Identity storage idt = identities[id];
        if (idt.status == Status.NONE) revert UnknownIdentity();
        require(
            msg.sender == idt.controller || hasRole(IDENTITY_ADMIN_ROLE, msg.sender),
            "not controller or admin"
        );
        if (byController[newKey] != 0) revert WalletAlreadyBound();

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            keccak256(abi.encodePacked(block.chainid, address(this), id, newKey, rotationNonce[id]))
        );
        if (digest.recover(sigFromNewKey) != newKey) revert BadRotationSignature();

        address old = idt.controller;
        rotationNonce[id] += 1;
        delete byController[old];
        byController[newKey] = id;
        idt.controller = newKey;

        _transferSoulbound(old, newKey, id);
        emit ControllerRotated(id, old, newKey);
    }

    function registerEncryptionKey(bytes32 x25519Pub) external {
        uint256 id = byController[msg.sender];
        if (id == 0) revert UnknownIdentity();
        identities[id].x25519Pub = x25519Pub;
        emit EncryptionKeyRegistered(id, x25519Pub);
    }

    // ------------------------------------------------------------- status/MAC

    /// @notice Fast path. Availability loss is safer than confidentiality loss,
    ///         so suspension is unilateral; un-suspending needs the full workflow.
    function suspend(uint256 id) external onlyRole(SECURITY_OFFICER_ROLE) {
        _setStatus(id, Status.SUSPENDED);
    }

    function reinstate(uint256 id) external onlyRole(IDENTITY_ADMIN_ROLE) {
        _setStatus(id, Status.ACTIVE);
    }

    function revoke(uint256 id) external onlyRole(SECURITY_OFFICER_ROLE) {
        _setStatus(id, Status.REVOKED);
        _burn(id);
        delete byController[identities[id].controller];
    }

    function setClearance(uint256 id, uint8 clearance) external onlyRole(IDENTITY_ADMIN_ROLE) {
        if (clearance > 4) revert ClearanceOutOfRange();
        uint8 prev = identities[id].clearance;
        identities[id].clearance = clearance;
        emit ClearanceChanged(id, prev, clearance);
    }

    function _setStatus(uint256 id, Status s) private {
        Identity storage idt = identities[id];
        if (idt.status == Status.NONE) revert UnknownIdentity();
        Status prev = idt.status;
        idt.status = s;
        emit StatusChanged(id, prev, s);
    }

    // ----------------------------------------------------------------- reads

    function isActive(uint256 id) public view returns (bool) {
        Identity storage idt = identities[id];
        return idt.status == Status.ACTIVE
            && (idt.validUntil == 0 || idt.validUntil > block.timestamp);
    }

    function clearanceOf(uint256 id) external view returns (uint8) {
        return identities[id].clearance;
    }

    function unitOf(uint256 id) external view returns (bytes32) {
        return identities[id].unitId;
    }

    function controllerOf(uint256 id) external view returns (address) {
        return identities[id].controller;
    }

    function totalIssued() external view returns (uint256) {
        return _nextId - 1;
    }

    // ------------------------------------------------------------- soulbound

    bool private _internalMove;

    function _transferSoulbound(address from, address to, uint256 id) private {
        _internalMove = true;
        _transfer(from, to, id);
        _internalMove = false;
    }

    function _update(address to, uint256 tokenId, address auth)
        internal
        override
        returns (address)
    {
        address from = _ownerOf(tokenId);
        // mint, burn and controller rotation are the only legal movements
        if (from != address(0) && to != address(0) && !_internalMove) revert Soulbound();
        return super._update(to, tokenId, auth);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }

    function supportsInterface(bytes4 iid)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(iid);
    }
}
