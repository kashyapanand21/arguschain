// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title AuditAnchor
/// @notice Merkle roots of off-chain audit-log batches (Section 9.2). Reads
///         and denials are too frequent to write individually, so each
///         decision is appended to a hash-chained off-chain table and a
///         Merkle root is anchored here once per ~1,000 lines or five
///         minutes. Any single line stays provable against the chain with a
///         Merkle proof, and the gas bill stays sane at BEL's volume.
contract AuditAnchor is AccessControl {
    /// @dev Anchor-only: this role can append roots and incidents and nothing
    ///      else. A stolen relayer key burns gas and nothing more (Section 9.2).
    bytes32 public constant ANCHOR_ROLE = keccak256("ANCHOR_ROLE");

    struct Batch {
        bytes32 merkleRoot;
        uint64  fromId;
        uint64  toId;
        uint64  anchoredAt;
        bytes32 prevRoot; // chains batches together
    }

    uint256 public batchCount;
    mapping(uint256 => Batch) public batches;
    bytes32 public latestRoot;

    struct Incident {
        bytes32 detailsHash;
        uint64  raisedAt;
        uint8   severity;
    }

    uint256 public incidentCount;
    mapping(uint256 => Incident) public incidents;

    event BatchAnchored(uint256 indexed batchId, bytes32 merkleRoot, uint64 fromId, uint64 toId, bytes32 prevRoot);
    event IncidentRecorded(uint256 indexed incidentId, bytes32 detailsHash, uint8 severity);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ANCHOR_ROLE, admin);
    }

    function anchor(bytes32 merkleRoot, uint64 fromId, uint64 toId)
        external
        onlyRole(ANCHOR_ROLE)
        returns (uint256 batchId)
    {
        batchId = ++batchCount;
        batches[batchId] = Batch(merkleRoot, fromId, toId, uint64(block.timestamp), latestRoot);
        emit BatchAnchored(batchId, merkleRoot, fromId, toId, latestRoot);
        latestRoot = merkleRoot;
    }

    function recordIncident(bytes32 detailsHash, uint8 severity)
        external
        onlyRole(ANCHOR_ROLE)
        returns (uint256 incidentId)
    {
        incidentId = ++incidentCount;
        incidents[incidentId] = Incident(detailsHash, uint64(block.timestamp), severity);
        emit IncidentRecorded(incidentId, detailsHash, severity);
    }

    /// @notice Verify a single audit line against an anchored batch root.
    function verify(uint256 batchId, bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i; i < proof.length; ++i) {
            bytes32 p = proof[i];
            computed = computed <= p
                ? keccak256(abi.encodePacked(computed, p))
                : keccak256(abi.encodePacked(p, computed));
        }
        return computed == batches[batchId].merkleRoot;
    }
}
