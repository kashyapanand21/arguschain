import { ethers } from "hardhat";

export const P = {
  LIST:      1 << 0,
  READ_META: 1 << 1,
  READ:      1 << 2,
  DOWNLOAD:  1 << 3,
  WRITE:     1 << 4,
  SHARE:     1 << 5,
  ADMIN:     1 << 6,
  AUDIT:     1 << 7,
};
export const CONTENT_BITS = P.READ | P.DOWNLOAD | P.WRITE;

export const CLASSIFICATION = {
  PUBLIC: 0,
  RESTRICTED: 1,
  CONFIDENTIAL: 2,
  SECRET: 3,
  TOP_SECRET: 4,
};

export const ROLE = {
  ADMIN: 1,
  MANAGER: 2,
  AUDITOR: 3,
  USER: 4,
  SECURITY_OFFICER: 5,
};

export enum PrincipalType {
  NONE = 0,
  IDENTITY = 1,
  ROLE = 2,
}

export function principalOf(type: PrincipalType, id: bigint | number): string {
  return ethers.solidityPackedKeccak256(["uint8", "uint256"], [type, id]);
}

export const principals = {
  identity: (id: bigint | number) => principalOf(PrincipalType.IDENTITY, id),
  role: (roleId: bigint | number) => principalOf(PrincipalType.ROLE, roleId),
};

export const justify = (text: string) => ethers.keccak256(ethers.toUtf8Bytes(text));
export const empCommitment = (empNo: string, salt: string) =>
  ethers.keccak256(ethers.toUtf8Bytes(`${empNo}:${salt}`));
export const contentHashOf = (text: string) => ethers.keccak256(ethers.toUtf8Bytes(text));

/// EIP-712 domain + types for ArgusIdentity.registerIdentity's Register message.
export function registerDomain(chainId: number | bigint, verifyingContract: string) {
  return { name: "ArgusIdentity", version: "4", chainId, verifyingContract };
}

export const REGISTER_TYPES = {
  Register: [
    { name: "did", type: "address" },
    { name: "empCommitment", type: "bytes32" },
    { name: "clearance", type: "uint8" },
    { name: "validUntil", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

/// Signs the Register message with the wallet that currently owns `did` on the
/// DID registry (normally the did address itself, unless its key has rotated).
export async function signRegister(
  didOwnerSigner: any,
  identityContract: any,
  did: string,
  empCommitmentHash: string,
  clearance: number,
  validUntil: bigint,
  nonce: bigint,
  deadline: bigint
): Promise<string> {
  const network = await didOwnerSigner.provider.getNetwork();
  const domain = registerDomain(network.chainId, await identityContract.getAddress());
  const value = { did, empCommitment: empCommitmentHash, clearance, validUntil, nonce, deadline };
  return didOwnerSigner.signTypedData(domain, REGISTER_TYPES, value);
}

export const FAR_FUTURE = 4102444800n; // 2100-01-01, used as a "no expiry" deadline in scripts/tests
