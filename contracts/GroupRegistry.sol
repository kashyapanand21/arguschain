// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title GroupRegistry
/// @notice Org units, project groups and need-to-know compartments.
/// @dev A group may carry a compartment tag. Compartment membership is what
///      gates the need-to-know check in the resolver - it is independent of
///      both grade and clearance.
contract GroupRegistry is AccessControl {
    bytes32 public constant ORG_ADMIN_ROLE = keccak256("ORG_ADMIN_ROLE");

    enum Kind { NONE, UNIT, PROJECT, COMPARTMENT }

    struct Group {
        string  label;
        bytes32 compartment; // 0 = no need-to-know restriction attached
        Kind    kind;
        bool    active;
    }

    mapping(uint256 => Group) public groups;
    mapping(uint256 => mapping(uint256 => bool)) public isMember;   // groupId => identityId
    mapping(uint256 => uint256[]) private _memberships;             // identityId => groupIds
    mapping(bytes32 => mapping(uint256 => bool)) public inCompartment; // compartment => identityId

    event GroupCreated(uint256 indexed groupId, string label, Kind kind, bytes32 compartment);
    event MemberAdded(uint256 indexed groupId, uint256 indexed identityId);
    event MemberRemoved(uint256 indexed groupId, uint256 indexed identityId);

    error UnknownGroup();

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ORG_ADMIN_ROLE, admin);
    }

    function createGroup(uint256 groupId, string calldata label, Kind kind, bytes32 compartment)
        external
        onlyRole(ORG_ADMIN_ROLE)
    {
        groups[groupId] = Group(label, compartment, kind, true);
        emit GroupCreated(groupId, label, kind, compartment);
    }

    function addMember(uint256 groupId, uint256 identityId) external onlyRole(ORG_ADMIN_ROLE) {
        Group storage g = groups[groupId];
        if (!g.active) revert UnknownGroup();
        if (isMember[groupId][identityId]) return;

        isMember[groupId][identityId] = true;
        _memberships[identityId].push(groupId);
        if (g.compartment != bytes32(0)) inCompartment[g.compartment][identityId] = true;
        emit MemberAdded(groupId, identityId);
    }

    function removeMember(uint256 groupId, uint256 identityId) external onlyRole(ORG_ADMIN_ROLE) {
        if (!isMember[groupId][identityId]) return;
        isMember[groupId][identityId] = false;

        uint256[] storage arr = _memberships[identityId];
        for (uint256 i; i < arr.length; ++i) {
            if (arr[i] == groupId) { arr[i] = arr[arr.length - 1]; arr.pop(); break; }
        }

        bytes32 comp = groups[groupId].compartment;
        if (comp != bytes32(0)) {
            // only drop the compartment if no remaining group grants it
            bool still;
            for (uint256 i; i < arr.length; ++i) {
                if (groups[arr[i]].compartment == comp) { still = true; break; }
            }
            if (!still) inCompartment[comp][identityId] = false;
        }
        emit MemberRemoved(groupId, identityId);
    }

    function groupsOf(uint256 identityId) external view returns (uint256[] memory) {
        return _memberships[identityId];
    }

    function hasCompartment(bytes32 compartment, uint256 identityId) external view returns (bool) {
        return compartment == bytes32(0) || inCompartment[compartment][identityId];
    }
}
