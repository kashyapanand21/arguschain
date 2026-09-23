import { ethers } from "ethers";
import fs from "fs";
import path from "path";

const ROOT = path.resolve(__dirname, "../..");
const NETWORK = process.env.CHAIN_NETWORK || "localhost";

const deployment = JSON.parse(
  fs.readFileSync(path.join(ROOT, "deployments", `${NETWORK}.json`), "utf8")
);

// contract name -> path of its .sol file inside contracts/
const SOURCES: Record<string, string> = {
  EthereumDIDRegistry: "identity/EthereumDIDRegistry.sol",
  ArgusIdentity: "ArgusIdentity.sol",
  RoleRegistry: "RoleRegistry.sol",
  AssetNFT: "AssetNFT.sol",
  AccessRegistry: "AccessRegistry.sol",
  GrantWorkflow: "GrantWorkflow.sol",
  AuditAnchor: "AuditAnchor.sol",
};

function abiOf(name: string) {
  const file = path.join(ROOT, "artifacts", "contracts", SOURCES[name], `${name}.json`);
  return JSON.parse(fs.readFileSync(file, "utf8")).abi;
}

export const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545");

const at = (name: string) => new ethers.Contract(deployment.contracts[name], abiOf(name), provider);

export const contracts = {
  didRegistry: at("EthereumDIDRegistry"),
  identity: at("ArgusIdentity"),
  roles: at("RoleRegistry"),
  assets: at("AssetNFT"),
  access: at("AccessRegistry"),
  workflow: at("GrantWorkflow"),
  audit: at("AuditAnchor"),
};

export const addresses = deployment.contracts; // the frontend will need these too
export const startBlock: number = deployment.startBlock ?? 0;