import "dotenv/config";
import fs from "fs";
import path from "path";
import { ethers } from "ethers";
import { SiweMessage } from "siwe";
import { contracts, provider } from "../chain";

const API = "http://localhost:3000";
const ADMIN_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async function login(wallet: ethers.Wallet) {
  const { nonce } = await (await fetch(`${API}/auth/nonce`)).json();
  const message = new SiweMessage({
    domain: process.env.SIWE_DOMAIN, address: wallet.address,
    statement: "Sign in to ArgusChain", uri: `http://${process.env.SIWE_DOMAIN}`,
    version: "1", chainId: 31337, nonce,
  }).prepareMessage();
  const res = await fetch(`${API}/auth/verify`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, signature: await wallet.signMessage(message) }),
  });
  const body = await res.json();
  if (!body.token) throw new Error(JSON.stringify(body));
  return body.token as string;
}
async function main() {
  const file = process.argv[2];
  const toIdentity = process.argv[3] ?? "2";          // default: Manager
  const classification = Number(process.argv[4] ?? 1); // default: RESTRICTED

  const wallet = new ethers.Wallet(ADMIN_KEY, provider);
  const jwt = await login(wallet);

  // 1. upload: encrypt and store, get the hash for the mint
  const form = new FormData();
  form.append("file", new Blob([fs.readFileSync(file)]), path.basename(file));
  const up = await (await fetch(`${API}/assets/upload`, {
    method: "POST", headers: { Authorization: `Bearer ${jwt}` }, body: form,
  })).json();
  if (!up.contentHash) throw new Error(JSON.stringify(up));
  console.log("1. uploaded:", up.contentHash);

  // 2. mint: the only step that writes to the chain (MetaMask does this in the real flow)
  const assets = contracts.assets.connect(wallet) as any;
  const justification = ethers.keccak256(ethers.toUtf8Bytes(`upload ${path.basename(file)}`));
  await (await assets.mint(toIdentity, up.contentHash, classification, justification)).wait();
  const tokenId = (await contracts.assets.totalMinted()).toString();
  console.log(`2. minted tokenId ${tokenId} to identity ${toIdentity}, classification ${classification}`);

  // 3. link: bind the stored file to the tokenId (the backend re-checks the hash on chain)
  const link = await (await fetch(`${API}/assets/${tokenId}/link`, {
    method: "POST",
    headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
    body: JSON.stringify(up),
  })).json();
  console.log("3. linked:", JSON.stringify(link));
  console.log(`\ntry: npx ts-node src/dev/login.ts <key> /assets/${tokenId}/content`);
}

main().catch((e) => {
  const selector = e?.data ?? e?.info?.error?.data;
  if (selector) {
    const parsed = contracts.assets.interface.parseError(selector);
    console.error(`reverted: ${parsed?.name ?? selector}`);
  } else {
    console.error(e.message);
  }
  process.exit(1);
});