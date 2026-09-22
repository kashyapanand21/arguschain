import { Request, Response, Router } from "express";
import { generateNonce, SiweMessage } from "siwe";
import jwt from "jsonwebtoken";

const router = Router();

// In a real app, store nonces in Redis or DB with an expiration
const nonceStore: Record<string, string> = {};

const JWT_SECRET = process.env.JWT_SECRET || "super-secret-jwt-key";

router.get("/nonce", (req: Request, res: Response) => {
  const nonce = generateNonce();
  const sessionId = Math.random().toString(36).substring(2); // Simple session id
  nonceStore[sessionId] = nonce;
  
  res.json({ nonce, sessionId });
});

router.post("/verify", async (req: Request, res: Response) => {
  try {
    const { message, signature, sessionId } = req.body;
    
    if (!message || !signature || !sessionId) {
      return res.status(422).json({ error: "Expected message, signature, and sessionId" });
    }

    const expectedNonce = nonceStore[sessionId];
    if (!expectedNonce) {
      return res.status(401).json({ error: "Invalid or expired session" });
    }

    const siweMessage = new SiweMessage(message);
    const verification = await siweMessage.verify({
      signature,
      nonce: expectedNonce,
    });

    const { data } = verification;
    
    // In ArgusChain v4, we also need to check the DID registry on-chain here
    // require didRegistry.identityOwner(did) == data.address
    // For now, we assume the signature proves control of the address.
    
    // Clean up nonce
    delete nonceStore[sessionId];

    // Issue JWT
    const token = jwt.sign(
      { address: data.address, did: `did:ethr:${data.address}` },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ success: true, token, did: `did:ethr:${data.address}` });
  } catch (e: any) {
    console.error("SIWE verification failed:", e);
    res.status(401).json({ error: e.message || "Invalid signature" });
  }
});

export default router;
