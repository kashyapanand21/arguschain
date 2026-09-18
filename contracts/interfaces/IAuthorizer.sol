// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IAuthorizer {
    function effectivePermissions(bytes32 node, address account) external view returns (uint32);
}
