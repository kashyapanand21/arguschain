import "dotenv/config";
import { Wallet } from "ethers";
import { SiweMessage } from "siwe";

const API = "http://localhost:3000";

async function main() {
  const wallet = new Wallet(process.argv[2]); // a private key from the hardhat node list
  const { nonce } = await (await fetch(`${API}/auth/nonce`)).json();

  const message = new SiweMessage({
    domain: process.env.SIWE_DOMAIN,
    address: wallet.address,
    statement: "Sign in to ArgusChain",
    uri: `http://${process.env.SIWE_DOMAIN}`,
    version: "1",
    chainId: 31337,
    nonce,
  }).prepareMessage();

  const signature = await wallet.signMessage(message);
  const res = await fetch(`${API}/auth/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, signature }),
  });
  const body = await res.json();
  console.log(res.status, JSON.stringify(body, null, 2));

  const path = process.argv[3];
  if (body.token && path) {
    const headers: Record<string, string> = { Authorization: `Bearer ${body.token}` };
    if (process.argv[4] === "stepup") headers["x-step-up"] = "verified";
    const r = await fetch(`${API}${path}`, { headers });
    const text = await r.text();
    console.log("\n", path, r.status, text.slice(0, 500));
      return;
      console.log("\n", path, r.status, JSON.stringify(await r.json(), null, 2));
  }}

main();