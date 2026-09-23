import crypto from "crypto";
import fs from "fs";
import path from "path";

const DIR = path.resolve(__dirname, "../storage");
const KEK = crypto.createHash("sha256").update(process.env.KEK_SECRET || "argus-demo-kek").digest();

fs.mkdirSync(DIR, { recursive: true });

function seal(key: Buffer, data: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([c.update(data), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]); // 12 + 16 + n
}

function open(key: Buffer, blob: Buffer): Buffer {
  const d = crypto.createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
  d.setAuthTag(blob.subarray(12, 28));
  return Buffer.concat([d.update(blob.subarray(28)), d.final()]);
}

export function sha256(buf: Buffer) {
  return "0x" + crypto.createHash("sha256").update(buf).digest("hex");
}

export function encryptAndStore(plaintext: Buffer) {
  const dek = crypto.randomBytes(32);
  const contentHash = sha256(plaintext);
  const storagePath = path.join(DIR, `${contentHash.slice(2)}.enc`);
  fs.writeFileSync(storagePath, seal(dek, plaintext));
  return { contentHash, storagePath, wrappedDek: seal(KEK, dek).toString("base64") };
}

export function loadAndDecrypt(storagePath: string, wrappedDek: string) {
  const dek = open(KEK, Buffer.from(wrappedDek, "base64"));
  return open(dek, fs.readFileSync(storagePath));
}