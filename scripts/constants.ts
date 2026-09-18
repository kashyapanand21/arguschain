import { ethers } from "hardhat";

export const P = {
  LIST: 1 << 0,
  READ_META: 1 << 1,
  READ: 1 << 2,
  DOWNLOAD: 1 << 3,
  WRITE: 1 << 4,
  CREATE: 1 << 5,
  DELETE: 1 << 6,
  SHARE: 1 << 7,
  ADMIN: 1 << 8,
  AUDIT: 1 << 9,
};

export const CLASSIFICATION = {
  PUBLIC: 0,
  RESTRICTED: 1,
  CONFIDENTIAL: 2,
  SECRET: 3,
  TOP_SECRET: 4,
};

export const PrincipalType = {
  NONE: 0,
  IDENTITY: 1,
  DESIGNATION: 2,
  GROUP: 3,
  UNIT: 4,
};

export const ROOT = ethers.ZeroHash;

export function principalOf(type: number, id: bigint | number | string): string {
  return ethers.solidityPackedKeccak256(["uint8", "uint256"], [type, id]);
}

export const principals = {
  identity: (id: bigint | number) => principalOf(PrincipalType.IDENTITY, id),
  designation: (id: bigint | number) => principalOf(PrincipalType.DESIGNATION, id),
  group: (id: bigint | number) => principalOf(PrincipalType.GROUP, id),
  unit: (unitId: string) => principalOf(PrincipalType.UNIT, BigInt(unitId)),
};

export const labelHash = (label: string) => ethers.keccak256(ethers.toUtf8Bytes(label));

/** nodeId = keccak256(parent || labelHash) — the same fold the client performs. */
export function nodeId(parent: string, label: string): string {
  return ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [parent, labelHash(label)]);
}

/** Fold a whole path: "/BEL/Ghaziabad/RADAR-X" -> one bytes32, zero RPC calls. */
export function pathToNodeId(path: string): string {
  return path
    .split("/")
    .filter(Boolean)
    .reduce((parent, label) => nodeId(parent, label), ROOT);
}

export const unitId = (name: string) => ethers.keccak256(ethers.toUtf8Bytes(name));
export const compartment = (name: string) => ethers.keccak256(ethers.toUtf8Bytes(name));
export const justify = (text: string) => ethers.keccak256(ethers.toUtf8Bytes(text));
export const empCommitment = (empNo: string, salt: string) =>
  ethers.keccak256(ethers.toUtf8Bytes(`${empNo}:${salt}`));

/** The BEL designation ladder. Grade sets a ceiling; the ACL grants the access. */
export const DESIGNATIONS = [
  { id: 1, label: "Chairman & Managing Director", grade: 10, ceiling: 4, functional: false },
  { id: 2, label: "Director", grade: 9, ceiling: 4, functional: false },
  { id: 3, label: "Executive Director", grade: 8, ceiling: 3, functional: false },
  { id: 4, label: "General Manager", grade: 7, ceiling: 3, functional: false },
  { id: 5, label: "Deputy General Manager", grade: 6, ceiling: 3, functional: false },
  { id: 6, label: "Senior Manager", grade: 5, ceiling: 2, functional: false },
  { id: 7, label: "Manager", grade: 4, ceiling: 2, functional: false },
  { id: 8, label: "Deputy Manager", grade: 3, ceiling: 2, functional: false },
  { id: 9, label: "Senior Engineer", grade: 2, ceiling: 1, functional: false },
  { id: 10, label: "Engineer", grade: 1, ceiling: 1, functional: false },
  { id: 20, label: "Internal Auditor", grade: 0, ceiling: 4, functional: true },
  { id: 21, label: "SOC Analyst", grade: 0, ceiling: 0, functional: true },
  { id: 22, label: "Security Officer", grade: 0, ceiling: 0, functional: true },
  { id: 23, label: "Asset Custodian", grade: 0, ceiling: 2, functional: true },
];

export const SECURITY_OFFICER = 22;
export const INTERNAL_AUDITOR = 20;
export const ASSET_CUSTODIAN = 23;
