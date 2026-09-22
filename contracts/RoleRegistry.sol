// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title RoleRegistry
/// @notice The four problem-statement roles (Admin, Manager, Auditor, User)
///         plus one extension (Security Officer), as non-transferable ERC-1155
///         tokens. Granting a role is a mint, revoking is a burn, and peer
///         transfer is disabled — a role can never leave the org through a
///         wallet (Section 5.2).
/// @dev Bootstrap problem: minting requires holding Admin, but no one holds
///      Admin yet at deploy time. bootstrap() is the one-time escape hatch,
///      gated by plain OZ AccessControl held only by the deployer, who should
///      renounce DEFAULT_ADMIN_ROLE immediately after (Section 11.1).
contract RoleRegistry is ERC1155, AccessControl {
    bytes32 public constant GRANT_EXECUTOR_ROLE = keccak256("GRANT_EXECUTOR_ROLE"); // GrantWorkflow only

    uint256 public constant ADMIN            = 1;
    uint256 public constant MANAGER          = 2;
    uint256 public constant AUDITOR          = 3;
    uint256 public constant USER             = 4;
    uint256 public constant SECURITY_OFFICER = 5;

    bool public bootstrapped;

    event RoleTokenGranted(address indexed to, uint256 indexed roleId, address indexed by);
    event RoleTokenRevoked(address indexed from, uint256 indexed roleId, address indexed by);

    error AlreadyBootstrapped();
    error NotAdmin();
    error UseWorkflowForAdminGrant();
    error UnknownRole();
    error Soulbound();

    constructor(address admin) ERC1155("") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    modifier onlyPlatformAdmin() {
        if (balanceOf(msg.sender, ADMIN) == 0) revert NotAdmin();
        _;
    }

    /// @notice One-time seed of the first Admin.
    function bootstrap(address founder) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (bootstrapped) revert AlreadyBootstrapped();
        bootstrapped = true;
        _mint(founder, ADMIN, 1, "");
        emit RoleTokenGranted(founder, ADMIN, msg.sender);
    }

    /// @notice Direct grant for Manager, Auditor, User and Security Officer.
    ///         Minting a new Admin cannot go through this path — an
    ///         ADMIN_ROLE_MINT proposal through GrantWorkflow is required
    ///         (Section 5.7), because a second Admin is itself a privileged,
    ///         four-eyes-worthy event.
    function grantRoleToken(address to, uint256 roleId) external onlyPlatformAdmin {
        if (roleId == ADMIN) revert UseWorkflowForAdminGrant();
        if (roleId == 0 || roleId > SECURITY_OFFICER) revert UnknownRole();
        if (balanceOf(to, roleId) == 0) _mint(to, roleId, 1, "");
        emit RoleTokenGranted(to, roleId, msg.sender);
    }

    function revokeRoleToken(address from, uint256 roleId) external onlyPlatformAdmin {
        if (roleId == 0 || roleId > SECURITY_OFFICER) revert UnknownRole();
        if (balanceOf(from, roleId) > 0) _burn(from, roleId, 1);
        emit RoleTokenRevoked(from, roleId, msg.sender);
    }

    /// @notice Privileged path used by GrantWorkflow.execute() for
    ///         ADMIN_ROLE_MINT proposals only.
    function executeAdminGrant(address to) external onlyRole(GRANT_EXECUTOR_ROLE) {
        if (balanceOf(to, ADMIN) == 0) _mint(to, ADMIN, 1, "");
        emit RoleTokenGranted(to, ADMIN, msg.sender);
    }

    function hasRoleToken(address who, uint256 roleId) external view returns (bool) {
        return balanceOf(who, roleId) > 0;
    }

    // ------------------------------------------------------------- soulbound

    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        override
    {
        if (from != address(0) && to != address(0)) revert Soulbound();
        super._update(from, to, ids, values);
    }

    function supportsInterface(bytes4 iid) public view override(ERC1155, AccessControl) returns (bool) {
        return super.supportsInterface(iid);
    }
}
