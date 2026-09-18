// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ArgusIdentity} from "./ArgusIdentity.sol";

/// @title DesignationRegistry
/// @notice Rank designations and functional roles as non-transferable ERC-1155.
/// @dev Two axes, deliberately separate:
///      - rank designation  : exactly one active per identity, carries a grade
///      - functional role   : many allowed, grade 0, defines what job you do
///      Canonical state is keyed by identityId; the ERC-1155 balance is minted
///      to the controller purely so the badge shows up in a wallet.
contract DesignationRegistry is ERC1155, AccessControl {
    bytes32 public constant ORG_ADMIN_ROLE = keccak256("ORG_ADMIN_ROLE");

    struct Designation {
        string  label;
        uint8   grade;               // 0 for functional roles
        uint8   clearanceCeiling;    // grade sets a ceiling, never the grant
        bool    functionalRole;
        bool    active;
    }

    ArgusIdentity public immutable identity;

    mapping(uint256 => Designation) public designations;
    mapping(uint256 => uint256[])   private _held;        // identityId => designationIds
    mapping(uint256 => mapping(uint256 => bool)) public holds; // identityId => did => bool
    mapping(uint256 => uint256)     public rankOf;        // identityId => rank designationId

    event DesignationDefined(uint256 indexed id, string label, uint8 grade, bool functionalRole);
    event DesignationAssigned(uint256 indexed identityId, uint256 indexed designationId);
    event DesignationRevoked(uint256 indexed identityId, uint256 indexed designationId);

    error Soulbound();
    error UnknownDesignation();
    error AlreadyHeld();
    error NotHeld();

    constructor(address admin, ArgusIdentity identity_) ERC1155("") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ORG_ADMIN_ROLE, admin);
        identity = identity_;
    }

    function defineDesignation(
        uint256 id,
        string calldata label,
        uint8 grade,
        uint8 clearanceCeiling,
        bool functionalRole
    ) external onlyRole(ORG_ADMIN_ROLE) {
        designations[id] = Designation(label, grade, clearanceCeiling, functionalRole, true);
        emit DesignationDefined(id, label, grade, functionalRole);
    }

    function assign(uint256 identityId, uint256 designationId) external onlyRole(ORG_ADMIN_ROLE) {
        Designation storage d = designations[designationId];
        if (!d.active) revert UnknownDesignation();
        if (holds[identityId][designationId]) revert AlreadyHeld();

        // one active rank at a time; functional roles stack
        if (!d.functionalRole) {
            uint256 current = rankOf[identityId];
            if (current != 0) _revoke(identityId, current);
            rankOf[identityId] = designationId;
        }

        holds[identityId][designationId] = true;
        _held[identityId].push(designationId);
        _mintTo(identityId, designationId);
        emit DesignationAssigned(identityId, designationId);
    }

    function revokeDesignation(uint256 identityId, uint256 designationId)
        external
        onlyRole(ORG_ADMIN_ROLE)
    {
        if (!holds[identityId][designationId]) revert NotHeld();
        _revoke(identityId, designationId);
    }

    function _revoke(uint256 identityId, uint256 designationId) private {
        holds[identityId][designationId] = false;
        uint256[] storage arr = _held[identityId];
        for (uint256 i; i < arr.length; ++i) {
            if (arr[i] == designationId) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                break;
            }
        }
        if (rankOf[identityId] == designationId) rankOf[identityId] = 0;
        address holder = identity.controllerOf(identityId);
        if (holder != address(0) && balanceOf(holder, designationId) > 0) {
            _burn(holder, designationId, 1);
        }
        emit DesignationRevoked(identityId, designationId);
    }

    function _mintTo(uint256 identityId, uint256 designationId) private {
        address holder = identity.controllerOf(identityId);
        if (holder != address(0)) _mint(holder, designationId, 1, "");
    }

    // ----------------------------------------------------------------- reads

    function designationsOf(uint256 identityId) external view returns (uint256[] memory) {
        return _held[identityId];
    }

    function gradeOf(uint256 identityId) external view returns (uint8) {
        uint256 rank = rankOf[identityId];
        return rank == 0 ? 0 : designations[rank].grade;
    }

    function hasDesignation(uint256 identityId, uint256 designationId) external view returns (bool) {
        return holds[identityId][designationId];
    }

    // ------------------------------------------------------------- soulbound

    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        override
    {
        if (from != address(0) && to != address(0)) revert Soulbound();
        super._update(from, to, ids, values);
    }

    function supportsInterface(bytes4 iid)
        public
        view
        override(ERC1155, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(iid);
    }
}
