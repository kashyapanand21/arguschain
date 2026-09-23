import "dotenv/config";
import fs from "fs";
import { Wallet } from "ethers";
import { SiweMessage } from "siwe";

const API = "http://localhost:3000";
const ADMIN_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async function token() {
  const wallet = new Wallet(ADMIN_KEY);
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
  return (await res.json()).token;
}

async function main() {
  const jwt = await token();
  const path = process.argv[2];
  const form = new FormData();
  form.append("file", new Blob([fs.readFileSync(path)]), path.split(/[\\/]/).pop());

  const res = await fetch(`${API}/assets/upload`, {
    method: "POST", headers: { Authorization: `Bearer ${jwt}` }, body: form,
  });
  const body = await res.json();
  console.log(res.status, JSON.stringify(body, null, 2));
  fs.writeFileSync("upload-result.json", JSON.stringify(body, null, 2));
}

main();

