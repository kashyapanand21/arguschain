// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ArgusIdentity} from "./ArgusIdentity.sol";
import {RoleRegistry} from "./RoleRegistry.sol";
import {IAuthorizer} from "./interfaces/IAuthorizer.sol";
import {Permissions} from "./libraries/Permissions.sol";
import {Principals} from "./libraries/Principals.sol";

/// @title AssetNFT
/// @notice Every digital asset is an ERC-721 NFT carrying an immutable SHA-256
///         content hash. Only an Admin-role holder can mint one, and it is
///         allocated directly to a registered identity. Ordinary transfers are
///         disabled — controlledTransfer/executeTransfer are the only paths
///         (Section 6).
/// @dev Two write paths per action, split at CONFIDENTIAL, mirroring how
///      AccessRegistry splits setAce vs executeGrant: PUBLIC/RESTRICTED is a
///      direct Admin-gated call; CONFIDENTIAL and above must come from
///      GrantWorkflow, because allocating or moving a classified asset is
///      itself an access grant (Section 6.1).
contract AssetNFT is ERC721, AccessControl {
    bytes32 public constant GRANT_EXECUTOR_ROLE = keccak256("GRANT_EXECUTOR_ROLE"); // GrantWorkflow only

    uint8 public constant CONFIDENTIAL = 2;
    uint8 public constant CLEARANCE_MAX = 4;

    struct Asset {
        bytes32 contentHash;
        uint8   classification; // 0 PUBLIC .. 4 TOP_SECRET
        uint32  version;
        uint256 ownerIdentity;
        uint64  mintedAt;
    }

    uint256 private _nextId = 1;
    mapping(uint256 => Asset)   public assets;
    mapping(bytes32 => uint256) public tokenOfHash; // the same content can never be minted twice

    ArgusIdentity public immutable identity;
    RoleRegistry  public immutable roles;
    IAuthorizer   public authorizer; // wired post-deploy to AccessRegistry

    event AssetMinted(uint256 indexed tokenId, uint256 indexed ownerIdentity, bytes32 contentHash, uint8 classification);
    event AssetTransferred(uint256 indexed tokenId, uint256 indexed fromIdentity, uint256 indexed toIdentity, bytes32 justification);
    event AssetVersioned(uint256 indexed tokenId, uint32 version, bytes32 oldHash, bytes32 newHash);

    error NotAdmin();
    error NotActiveIdentity();
    error InsufficientClearance();
    error ClassificationOutOfRange();
    error DuplicateContent();
    error RequiresWorkflow();
    error JustificationRequired();
    error Unauthorized();
    error UnknownAsset();
    error AuthorizerNotSet();
    error TransferDisabled();

    constructor(address identity_, address roles_, address admin) ERC721("ArgusChain Asset", "ARGUSASSET") {
        identity = ArgusIdentity(identity_);
        roles = RoleRegistry(roles_);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function setAuthorizer(IAuthorizer a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        authorizer = a;
    }

    /// @dev resourceId keys AccessRegistry's ACE table. Today it folds to the
    ///      tokenId 1:1; the v4.1 extension path (Section 13.2) can widen this
    ///      to a namehash folder-tree node id without touching the ACE struct.
    function resourceIdOf(uint256 tokenId) public pure returns (bytes32) {
        return bytes32(tokenId);
    }

    // ------------------------------------------------------------------ mint

    /// @notice Direct path for PUBLIC / RESTRICTED assets.
    function mint(uint256 toIdentity, bytes32 contentHash, uint8 classification, bytes32 justificationHash)
        external
        returns (uint256 tokenId)
    {
        if (roles.balanceOf(msg.sender, roles.ADMIN()) == 0) revert NotAdmin();
        if (classification >= CONFIDENTIAL) revert RequiresWorkflow();
        return _mintAsset(toIdentity, contentHash, classification, justificationHash);
    }

    /// @notice Privileged path used by GrantWorkflow.execute() for
    ///         MINT_AND_ALLOCATE proposals on CONFIDENTIAL and above.
    function executeMint(uint256 toIdentity, bytes32 contentHash, uint8 classification, bytes32 justificationHash)
        external
        onlyRole(GRANT_EXECUTOR_ROLE)
        returns (uint256 tokenId)
    {
        return _mintAsset(toIdentity, contentHash, classification, justificationHash);
    }

    function _mintAsset(uint256 toIdentity, bytes32 contentHash, uint8 classification, bytes32 justificationHash)
        private
        returns (uint256 tokenId)
    {
        if (classification > CLEARANCE_MAX) revert ClassificationOutOfRange();
        if (justificationHash == bytes32(0)) revert JustificationRequired();
        if (!identity.isActive(toIdentity)) revert NotActiveIdentity();
        if (identity.clearanceOf(toIdentity) < classification) revert InsufficientClearance();
        if (tokenOfHash[contentHash] != 0) revert DuplicateContent();

        tokenId = _nextId++;
        assets[tokenId] = Asset({
            contentHash: contentHash,
            classification: classification,
            version: 1,
            ownerIdentity: toIdentity,
            mintedAt: uint64(block.timestamp)
        });
        tokenOfHash[contentHash] = tokenId;

        address holder = identity.controllerOf(toIdentity);
        _mint(holder, tokenId);
        emit AssetMinted(tokenId, toIdentity, contentHash, classification);

        // Owner default per Section 6.1: P_LIST|P_READ_META|P_READ|P_DOWNLOAD|
        // P_WRITE|P_SHARE. Every Admin role-holder separately gets P_LIST|P_ADMIN
        // — ACL management rights, never a content bit — which is what "the
        // Admin who minted it receives none of the content bits" (Section 6.1)
        // implies it *does* receive, and is also what makes the asset's ACL
        // administrable at all before any further grant exists.
        if (address(authorizer) != address(0)) {
            authorizer.seedAce(
                resourceIdOf(tokenId), Principals.identity(toIdentity),
                Permissions.P_LIST | Permissions.P_READ_META | Permissions.P_READ | Permissions.P_DOWNLOAD |
                    Permissions.P_WRITE | Permissions.P_SHARE,
                justificationHash
            );
            authorizer.seedAce(
                resourceIdOf(tokenId), Principals.role(roles.ADMIN()),
                Permissions.P_LIST | Permissions.P_ADMIN,
                justificationHash
            );
        }
    }

    // --------------------------------------------------------------- transfer

    /// @notice Direct path for PUBLIC / RESTRICTED assets. Caller must hold
    ///         P_ADMIN on the resource.
    function controlledTransfer(uint256 tokenId, uint256 toIdentity, bytes32 justificationHash) external {
        Asset storage a = _asset(tokenId);
        if (a.classification >= CONFIDENTIAL) revert RequiresWorkflow();
        _requireBit(tokenId, Permissions.P_ADMIN);
        _doTransfer(tokenId, a, toIdentity, justificationHash);
    }

    /// @notice Privileged path used by GrantWorkflow.execute() for TRANSFER
    ///         proposals on CONFIDENTIAL and above.
    function executeTransfer(uint256 tokenId, uint256 toIdentity, bytes32 justificationHash)
        external
        onlyRole(GRANT_EXECUTOR_ROLE)
    {
        Asset storage a = _asset(tokenId);
        _doTransfer(tokenId, a, toIdentity, justificationHash);
    }

    function _doTransfer(uint256 tokenId, Asset storage a, uint256 toIdentity, bytes32 justificationHash) private {
        if (justificationHash == bytes32(0)) revert JustificationRequired();
        if (!identity.isActive(toIdentity)) revert NotActiveIdentity();
        if (identity.clearanceOf(toIdentity) < a.classification) revert InsufficientClearance();

        uint256 fromIdentity = a.ownerIdentity;
        a.ownerIdentity = toIdentity;
        address newHolder = identity.controllerOf(toIdentity);
        _update(newHolder, tokenId, address(0)); // internal move; public transfer entry points stay blocked below

                emit AssetTransferred(tokenId, fromIdentity, toIdentity, justificationHash);

        // Section 6.2: old owner's ACE is removed, new owner receives the owner default
        if (address(authorizer) != address(0)) {
            bytes32 rid = resourceIdOf(tokenId);
            authorizer.revokeAce(rid, Principals.identity(fromIdentity), type(uint256).max);
            authorizer.seedAce(
                rid, Principals.identity(toIdentity),
                Permissions.P_LIST | Permissions.P_READ_META | Permissions.P_READ | Permissions.P_DOWNLOAD |
                    Permissions.P_WRITE | Permissions.P_SHARE,
                justificationHash
            );
        }
    }

    function transferFrom(address, address, uint256) public pure override {
        revert TransferDisabled();
    }

    function safeTransferFrom(address, address, uint256, bytes memory) public pure override {
        revert TransferDisabled();
    }

    // ----------------------------------------------------------------- write

    /// @notice New version upload. Gated by P_WRITE, at every classification —
    ///         the write bit itself was only ever granted through the tiered
    ///         approval process that produced the underlying ACE.
    function updateContent(uint256 tokenId, bytes32 newHash, bytes32 justificationHash) external {
        Asset storage a = _asset(tokenId);
        if (justificationHash == bytes32(0)) revert JustificationRequired();
        _requireBit(tokenId, Permissions.P_WRITE);
        if (tokenOfHash[newHash] != 0) revert DuplicateContent();

        bytes32 old = a.contentHash;
        tokenOfHash[old] = 0;
        a.contentHash = newHash;
        a.version += 1;
        tokenOfHash[newHash] = tokenId;

        emit AssetVersioned(tokenId, a.version, old, newHash);
    }

    // ------------------------------------------------------------------ reads

    function classificationOf(uint256 tokenId) external view returns (uint8) {
        return assets[tokenId].classification;
    }

    function ownerIdentityOf(uint256 tokenId) external view returns (uint256) {
        return assets[tokenId].ownerIdentity;
    }

    function exists(uint256 tokenId) external view returns (bool) {
        return assets[tokenId].mintedAt != 0;
    }

    function totalMinted() external view returns (uint256) {
        return _nextId - 1;
    }

    // ------------------------------------------------------------------ auth

    function _requireBit(uint256 tokenId, uint32 bit) private view {
        if (address(authorizer) == address(0)) revert AuthorizerNotSet();
        if (authorizer.effectivePermissions(resourceIdOf(tokenId), msg.sender) & bit == 0) revert Unauthorized();
    }

    function _asset(uint256 tokenId) private view returns (Asset storage a) {
        a = assets[tokenId];
        if (a.mintedAt == 0) revert UnknownAsset();
    }

    function supportsInterface(bytes4 iid) public view override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(iid);
    }
}
