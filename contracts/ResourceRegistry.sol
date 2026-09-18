// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Permissions} from "./libraries/Permissions.sol";
import {IAuthorizer} from "./interfaces/IAuthorizer.sol";

/// @title ResourceRegistry
/// @notice The file explorer, on-chain: a namehash tree of folders and files.
/// @dev nodeId = keccak256(parent || labelHash). Path resolution is therefore a
///      pure client-side fold - /BEL/Ghaziabad/RADAR-X/specs.pdf becomes one
///      bytes32 with zero RPC round-trips. Labels never go on-chain.
contract ResourceRegistry is AccessControl {
    bytes32 public constant NODE_WRITER_ROLE = keccak256("NODE_WRITER_ROLE"); // relayer
    bytes32 public constant ROOT = bytes32(0);
    uint8   public constant MAX_DEPTH = 16;

    enum NodeType { NONE, ROOT, FOLDER, FILE }

    struct Node {
        bytes32  parent;
        bytes32  labelHash;
        NodeType nodeType;
        uint8    classification; // 0 PUBLIC .. 4 TOP_SECRET
        uint8    depth;
        bool     inheritanceEnabled;
        bool     active;
        bytes32  custodian;      // principal id
        bytes32  compartment;    // need-to-know tag, 0 = none
        bytes32  contentHash;    // SHA-256 of plaintext (FILE only)
        bytes32  keyBundleRoot;  // Merkle root of wrapped-DEK set
        uint64   version;
    }

    IAuthorizer public authorizer;

    mapping(bytes32 => Node) public nodes;
    mapping(bytes32 => bytes32[]) private _children;

    event NodeCreated(
        bytes32 indexed nodeId,
        bytes32 indexed parent,
        bytes32 labelHash,
        NodeType nodeType,
        uint8 classification,
        bytes32 compartment,
        bytes32 custodian
    );
    event ContentUpdated(bytes32 indexed nodeId, bytes32 contentHash, bytes32 keyBundleRoot, uint64 version);
    event InheritanceChanged(bytes32 indexed nodeId, bool enabled);
    event NodeDeactivated(bytes32 indexed nodeId);
    event ClassificationChanged(bytes32 indexed nodeId, uint8 previous, uint8 current);

    error NodeExists();
    error NoSuchParent();
    error ClassificationDecrease();
    error DepthExceeded();
    error NotAFolder();
    error Unauthorized();
    error UnknownNode();

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(NODE_WRITER_ROLE, admin);
        // synthesise the root so depth/classification maths has a base case
        nodes[ROOT] = Node({
            parent: bytes32(0),
            labelHash: bytes32(0),
            nodeType: NodeType.ROOT,
            classification: 0,
            depth: 0,
            inheritanceEnabled: true,
            active: true,
            custodian: bytes32(0),
            compartment: bytes32(0),
            contentHash: bytes32(0),
            keyBundleRoot: bytes32(0),
            version: 0
        });
    }

    function setAuthorizer(IAuthorizer a) external onlyRole(DEFAULT_ADMIN_ROLE) {
        authorizer = a;
    }

    function nodeId(bytes32 parent, bytes32 labelHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(parent, labelHash));
    }

    // -------------------------------------------------------------- mutations

    function createNode(
        bytes32 parent,
        bytes32 labelHash,
        NodeType nodeType,
        uint8   classification,
        bytes32 compartment,
        bytes32 custodian
    ) external returns (bytes32 id) {
        Node storage p = nodes[parent];
        if (!p.active || p.nodeType == NodeType.NONE) revert NoSuchParent();
        if (p.nodeType == NodeType.FILE) revert NotAFolder();
        _requireCreate(parent);

        // classification never decreases down the tree: a SECRET folder
        // cannot contain a PUBLIC file
        if (classification < p.classification) revert ClassificationDecrease();
        if (p.depth + 1 > MAX_DEPTH) revert DepthExceeded();

        id = nodeId(parent, labelHash);
        if (nodes[id].nodeType != NodeType.NONE) revert NodeExists();

        nodes[id] = Node({
            parent: parent,
            labelHash: labelHash,
            nodeType: nodeType,
            classification: classification,
            depth: p.depth + 1,
            inheritanceEnabled: true,
            active: true,
            custodian: custodian,
            // a child with no explicit compartment inherits the parent's
            compartment: compartment == bytes32(0) ? p.compartment : compartment,
            contentHash: bytes32(0),
            keyBundleRoot: bytes32(0),
            version: 0
        });
        _children[parent].push(id);

        emit NodeCreated(id, parent, labelHash, nodeType, classification, nodes[id].compartment, custodian);
    }

    function setContent(bytes32 id, bytes32 contentHash, bytes32 keyBundleRoot) external {
        Node storage n = _node(id);
        _requireBit(id, Permissions.P_WRITE);
        n.contentHash = contentHash;
        n.keyBundleRoot = keyBundleRoot;
        n.version += 1;
        emit ContentUpdated(id, contentHash, keyBundleRoot, n.version);
    }

    /// @dev The UI must snapshot inherited ACEs onto this node *before* calling
    ///      this, otherwise "lock this folder down" silently removes everyone's
    ///      access - including the admin's own.
    function setInheritance(bytes32 id, bool enabled) external {
        Node storage n = _node(id);
        _requireBit(id, Permissions.P_ADMIN);
        n.inheritanceEnabled = enabled;
        emit InheritanceChanged(id, enabled);
    }

    function setClassification(bytes32 id, uint8 classification) external {
        Node storage n = _node(id);
        _requireBit(id, Permissions.P_ADMIN);
        if (classification < nodes[n.parent].classification) revert ClassificationDecrease();
        bytes32[] storage kids = _children[id];
        for (uint256 i; i < kids.length; ++i) {
            if (nodes[kids[i]].classification < classification) revert ClassificationDecrease();
        }
        uint8 prev = n.classification;
        n.classification = classification;
        emit ClassificationChanged(id, prev, classification);
    }

    function deactivate(bytes32 id) external {
        Node storage n = _node(id);
        _requireBit(id, Permissions.P_DELETE);
        n.active = false;
        emit NodeDeactivated(id);
    }

    // ------------------------------------------------------------------ reads

    function childrenOf(bytes32 id) external view returns (bytes32[] memory) {
        return _children[id];
    }

    function get(bytes32 id) external view returns (Node memory) {
        return nodes[id];
    }

    function exists(bytes32 id) external view returns (bool) {
        return nodes[id].nodeType != NodeType.NONE;
    }

    function classificationOf(bytes32 id) external view returns (uint8) {
        return nodes[id].classification;
    }

    function compartmentOf(bytes32 id) external view returns (bytes32) {
        return nodes[id].compartment;
    }

    // ------------------------------------------------------------------ auth

    /// @dev Two write paths by design. The relayer (NODE_WRITER_ROLE) submits
    ///      transactions on the user's behalf after the gateway has run the PDP
    ///      and verified a step-up signature; a user calling directly is checked
    ///      against the live ACL.
    function _requireCreate(bytes32 parent) private view {
        if (hasRole(NODE_WRITER_ROLE, msg.sender)) return;
        if (address(authorizer) == address(0)) revert Unauthorized();
        if (authorizer.effectivePermissions(parent, msg.sender) & Permissions.P_CREATE == 0) {
            revert Unauthorized();
        }
    }

    function _requireBit(bytes32 id, uint32 bit) private view {
        if (hasRole(NODE_WRITER_ROLE, msg.sender)) return;
        if (address(authorizer) == address(0)) revert Unauthorized();
        if (authorizer.effectivePermissions(id, msg.sender) & bit == 0) revert Unauthorized();
    }

    function _node(bytes32 id) private view returns (Node storage n) {
        n = nodes[id];
        if (n.nodeType == NodeType.NONE) revert UnknownNode();
    }
}
