import { Request, Response, Router } from "express";
import { generateNonce, SiweMessage } from "siwe";
import jwt from "jsonwebtoken";
import { contracts } from "../chain";
import { ROLE_IDS, STATUS } from "../constants";
import { jwtSecret, requireAuth } from "../middleware/auth";

const router = Router();
const NONCE_TTL_MS = 5 * 60 * 1000;
const nonces = new Map<string, number>(); // nonce -> expiry timestamp

router.get("/nonce", (_req, res) => {
  const nonce = generateNonce();
  nonces.set(nonce, Date.now() + NONCE_TTL_MS);
  res.json({ nonce });
});

router.post("/verify", async (req: Request, res: Response) => {
  const { message, signature } = req.body ?? {};
  if (!message || !signature) return res.status(422).json({ code: "BAD_REQUEST" });

  // 1. Cryptographic proof: signature, domain, time window, single-use nonce
  let signer: string;
  try {
    const siwe = new SiweMessage(message);
    const expiry = nonces.get(siwe.nonce);
    if (!expiry || expiry < Date.now()) return res.status(401).json({ code: "NONCE_INVALID" });
    nonces.delete(siwe.nonce); // burned before verifying: no replay, even of a failed attempt
    const { data } = await siwe.verify({ signature, nonce: siwe.nonce, domain: process.env.SIWE_DOMAIN });
    signer = data.address;
  } catch {
    return res.status(401).json({ code: "BAD_SIGNATURE" });
  }

    // 2. Which identity does this key control *right now*? Read live from ERC-1056.
  const identityId: bigint = await contracts.identity.byController(signer);
  if (identityId === 0n) return res.status(401).json({ code: "IDENTITY_NOT_FOUND" });

  const record = await contracts.identity.identities(identityId);
  const liveOwner: string = await contracts.didRegistry.identityOwner(record.did);
  if (liveOwner.toLowerCase() !== signer.toLowerCase()) {
    return res.status(401).json({ code: "IDENTITY_NOT_FOUND" }); // rotated-away key
  }

    // 3. Status and tenure
  if (!(await contracts.identity.isActive(identityId))) {
    const status = Number(record.status);
    if (status === STATUS.SUSPENDED) return res.status(423).json({ code: "IDENTITY_SUSPENDED" });
    if (status === STATUS.REVOKED) return res.status(403).json({ code: "IDENTITY_REVOKED" });
    return res.status(403).json({ code: "IDENTITY_EXPIRED" });
  }

    // 4. Authorization context, only after authentication has passed
  const balances: bigint[] = await Promise.all(
    ROLE_IDS.map((r) => contracts.roles.balanceOf(signer, r))
  );
  const roles = ROLE_IDS.filter((_, i) => balances[i] > 0n);

  const session = {
    identityId: identityId.toString(),
    address: signer,
    did: `did:ethr:${record.did}`,
    roles,
    clearance: Number(record.clearance),
  };
  const token = jwt.sign(session, jwtSecret(), { expiresIn: "15m" });
  res.json({ token, session });
});

router.get("/me", requireAuth, (req, res) => res.json(req.user));

export default router;
