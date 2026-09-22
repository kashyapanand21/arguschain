import { ethers } from "ethers";
import { PrismaClient } from "@prisma/client";
import * as dotenv from "dotenv";

// Import ABIs (using require to avoid TS out-of-rootDir resolution issues if not configured)
const AccessRegistryArtifact = require("../../../artifacts/contracts/AccessRegistry.sol/AccessRegistry.json");
const ArgusIdentityArtifact = require("../../../artifacts/contracts/ArgusIdentity.sol/ArgusIdentity.json");
const AssetNFTArtifact = require("../../../artifacts/contracts/AssetNFT.sol/AssetNFT.json");
const RoleRegistryArtifact = require("../../../artifacts/contracts/RoleRegistry.sol/RoleRegistry.json");

dotenv.config();

const prisma = new PrismaClient();

// These should be updated once contracts are deployed locally
// For now, they are placeholders. In a real app, you'd read them from a deployments file.
const CONTRACT_ADDRESSES = {
  ArgusIdentity: process.env.ARGUS_IDENTITY_ADDR || ethers.ZeroAddress,
  RoleRegistry: process.env.ROLE_REGISTRY_ADDR || ethers.ZeroAddress,
  AssetNFT: process.env.ASSET_NFT_ADDR || ethers.ZeroAddress,
  AccessRegistry: process.env.ACCESS_REGISTRY_ADDR || ethers.ZeroAddress,
};

export class BlockchainIndexer {
  private provider: ethers.JsonRpcProvider;
  
  constructor() {
    this.provider = new ethers.JsonRpcProvider(process.env.RPC_URL || "http://127.0.0.1:8545");
  }

  async start() {
    console.log("[Indexer] Starting blockchain event listener...");
    
    // We only attach listeners if the addresses are configured (not ZeroAddress)
    if (CONTRACT_ADDRESSES.ArgusIdentity !== ethers.ZeroAddress) {
      this.listenToIdentityEvents();
      this.listenToAssetEvents();
      this.listenToRoleEvents();
      this.listenToAccessEvents();
    } else {
      console.warn("[Indexer] Contract addresses not configured. Skipping event listeners.");
    }
  }

  private listenToIdentityEvents() {
    const identityContract = new ethers.Contract(CONTRACT_ADDRESSES.ArgusIdentity, ArgusIdentityArtifact.abi, this.provider);
    
    // Listen for IdentityRegistered(uint256 indexed identityId, address indexed did, bytes32 empCommitment)
    identityContract.on("IdentityRegistered", async (identityId, did, empCommitment, event) => {
      console.log(`[Indexer] IdentityRegistered: ${identityId.toString()}`);
      try {
        const details = await identityContract.identities(identityId);
        await prisma.identity.upsert({
          where: { id: identityId.toString() },
          update: { status: "ACTIVE" }, // Simplified update
          create: {
            id: identityId.toString(),
            did: did,
            empCommitment: empCommitment,
            clearance: Number(details.clearance),
            status: "ACTIVE",
            issuedAt: new Date(Number(details.issuedAt) * 1000),
            validUntil: new Date(Number(details.validUntil) * 1000),
          }
        });
      } catch (err) {
        console.error("[Indexer] Error processing IdentityRegistered", err);
      }
    });
  }

  private listenToAssetEvents() {
    const assetContract = new ethers.Contract(CONTRACT_ADDRESSES.AssetNFT, AssetNFTArtifact.abi, this.provider);
    
    assetContract.on("AssetMinted", async (resourceId, ownerIdentity, classification, contentHash, event) => {
      console.log(`[Indexer] AssetMinted: ${resourceId.toString()}`);
      try {
        await prisma.asset.upsert({
          where: { id: resourceId.toString() },
          update: {},
          create: {
            id: resourceId.toString(),
            contentHash,
            ownerId: ownerIdentity.toString(),
            classification: Number(classification),
          }
        });
      } catch (err) {
        console.error("[Indexer] Error processing AssetMinted", err);
      }
    });
  }

  private listenToRoleEvents() {
    // Similar implementation for RoleRegistry events...
  }

  private listenToAccessEvents() {
    // Similar implementation for AccessRegistry events...
  }
}
