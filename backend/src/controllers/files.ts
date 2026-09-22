import { Request, Response, Router, NextFunction } from "express";
import multer from "multer";
import crypto from "crypto";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { PrismaClient } from "@prisma/client";

const router = Router();
const prisma = new PrismaClient();
const upload = multer({ storage: multer.memoryStorage() });

// Initialize Backblaze B2 S3 Client
const s3 = new S3Client({
  endpoint: process.env.B2_ENDPOINT || "https://s3.us-west-000.backblazeb2.com",
  region: "us-west-000",
  credentials: {
    accessKeyId: process.env.B2_ACCESS_KEY_ID || "",
    secretAccessKey: process.env.B2_SECRET_ACCESS_KEY || "",
  },
});

const B2_BUCKET = process.env.B2_BUCKET_NAME || "arguschain-assets";
const VAULT_MOCK_KEK = Buffer.from(process.env.VAULT_MOCK_KEK || "0123456789abcdef0123456789abcdef", "utf8");

// Mock JWT Auth Middleware
const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  // In reality, verify the JWT here
  req.body.userDid = req.headers["x-user-did"];
  next();
};

router.post("/upload", requireAuth, upload.single("file"), async (req: Request, res: Response) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: "No file uploaded" });

    // 1. Generate DEK (Data Encryption Key)
    const dek = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    // 2. Compute plaintext SHA-256 (this becomes the on-chain contentHash)
    const hashSum = crypto.createHash("sha256");
    hashSum.update(file.buffer);
    const contentHash = "0x" + hashSum.digest("hex");

    // 3. Encrypt file stream with DEK (AES-256-GCM)
    const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv);
    const encryptedBuffer = Buffer.concat([cipher.update(file.buffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    // Combine IV, AuthTag, and Encrypted Buffer to store in B2
    const finalBlob = Buffer.concat([iv, authTag, encryptedBuffer]);

    // 4. Store in Backblaze B2
    const storageKey = `assets/${contentHash}.enc`;
    await s3.send(new PutObjectCommand({
      Bucket: B2_BUCKET,
      Key: storageKey,
      Body: finalBlob,
    }));

    // 5. Wrap DEK with KEK
    const kekIv = crypto.randomBytes(12);
    const kekCipher = crypto.createCipheriv("aes-256-gcm", VAULT_MOCK_KEK, kekIv);
    const wrappedDekBuffer = Buffer.concat([kekCipher.update(dek), kekCipher.final()]);
    const kekAuthTag = kekCipher.getAuthTag();
    const wrappedDek = kekIv.toString("hex") + ":" + kekAuthTag.toString("hex") + ":" + wrappedDekBuffer.toString("hex");

    // 6. Return payload for the user to mint the NFT on-chain
    res.json({
      success: true,
      contentHash,
      storageKey,
      wrappedDek,
      message: "File encrypted and stored. Please submit AssetMinted transaction on-chain."
    });

  } catch (error: any) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Upload failed" });
  }
});

export default router;
