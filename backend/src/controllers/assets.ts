import { Router } from "express";
import multer from "multer";
import { contracts } from "../chain";
import { requireAuth } from "../middleware/auth";
import { authorize } from "../pdp";
import { P } from "../constants";
import { encryptAndStore, loadAndDecrypt, sha256 } from "../storage";
import { logDecision, prisma } from "../audit";
import { scoreRequest } from "../risk";

const router = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

const BITS: [string, number][] = [
  ["P_LIST", P.LIST], ["P_READ_META", P.READ_META], ["P_READ", P.READ], ["P_DOWNLOAD", P.DOWNLOAD],
  ["P_WRITE", P.WRITE], ["P_SHARE", P.SHARE], ["P_ADMIN", P.ADMIN], ["P_AUDIT", P.AUDIT],
];
const idOf = (raw: any) => (/^\d+$/.test(String(raw)) ? String(raw) : null);

router.get("/", requireAuth, async (req, res) => {
  const total = Number(await contracts.assets.totalMinted());
  const out = [];
  for (let id = 1; id <= total; id++) {
    const d = await authorize(req.user!, String(id), P.LIST);
    if (!d.allow) continue; // invisible: more than one level above clearance
    const a = await contracts.assets.assets(id);
    const file = await prisma.storedFile.findUnique({ where: { tokenId: String(id) } });
    out.push({
      tokenId: String(id),
      name: file?.name ?? `asset-${id}`,
      classification: Number(a.classification),
      ownerIdentity: a.ownerIdentity.toString(),
      version: Number(a.version),
      effective: `0x${d.effective.toString(16).padStart(2, "0")}`,
      locked: d.effective === P.LIST, // greyed entry, request-access only
    });
  }
  res.json(out);
});
router.get("/:id", requireAuth, async (req, res) => {
  const tokenId = idOf(req.params.id);
  if (!tokenId) return res.status(400).json({ code: "BAD_TOKEN_ID" });

  const d = await authorize(req.user!, tokenId, P.READ_META);
  if (!d.allow) return res.status(d.status).json({ code: d.code, detail: d.detail });

  const a = await contracts.assets.assets(tokenId);
  const file = await prisma.storedFile.findUnique({ where: { tokenId } });
  res.json({
    tokenId, name: file?.name, size: file?.size, mimeType: file?.mimeType,
    contentHash: a.contentHash, classification: Number(a.classification),
    version: Number(a.version), ownerIdentity: a.ownerIdentity.toString(),
    effective: `0x${d.effective.toString(16).padStart(2, "0")}`,
  });
});

router.get("/:id/effective", requireAuth, async (req, res) => {
  const tokenId = idOf(req.params.id);
  if (!tokenId) return res.status(400).json({ code: "BAD_TOKEN_ID" });

  const d = await authorize(req.user!, tokenId, P.LIST);
  res.json({
    tokenId, identityId: req.user!.identityId, clearance: req.user!.clearance,
    classification: Number(await contracts.assets.classificationOf(tokenId)),
    effective: `0x${d.effective.toString(16).padStart(2, "0")}`,
    denialCode: d.allow ? null : d.code,
    bits: BITS.map(([name, bit]) => ({ name, granted: (d.effective & bit) !== 0 })),
  });
});
router.get("/:id/acl", requireAuth, async (req, res) => {
  const tokenId = idOf(req.params.id);
  if (!tokenId) return res.status(400).json({ code: "BAD_TOKEN_ID" });

  const d = await authorize(req.user!, tokenId, P.ADMIN);
  const audit = await authorize(req.user!, tokenId, P.AUDIT);
  if (!d.allow && !audit.allow) return res.status(403).json({ code: "NO_ACL_ACCESS" });

  const resourceId = "0x" + BigInt(tokenId).toString(16).padStart(64, "0");
  const principals: string[] = await contracts.access.principalsOnResource(resourceId);
  const entries = await Promise.all(principals.map(async (p) => {
    const ace = await contracts.access.getAce(resourceId, p);
    return {
      principal: p,
      allow: `0x${Number(ace.allowMask).toString(16).padStart(2, "0")}`,
      deny: `0x${Number(ace.denyMask).toString(16).padStart(2, "0")}`,
      expiresAt: Number(ace.expiresAt) || null,
      grantedBy: ace.grantedBy.toString(),
      justificationHash: ace.justificationHash,
    };
  }));
  res.json(entries);
});
router.post("/upload", requireAuth, upload.single("file"), async (req, res) => {
  if (!req.user!.roles.includes(1)) return res.status(403).json({ code: "NOT_ADMIN" });
  if (!req.file) return res.status(400).json({ code: "NO_FILE" });

  const { contentHash, storagePath, wrappedDek } = encryptAndStore(req.file.buffer);
  res.json({
    contentHash, storagePath, wrappedDek,
    name: req.file.originalname, mimeType: req.file.mimetype, size: req.file.size,
    next: "Sign the mint transaction with this contentHash, then POST /assets/:id/link",
  });
});

/// Called after the mint transaction confirms, to bind the tokenId to the stored file.
router.post("/:id/link", requireAuth, async (req, res) => {
  const tokenId = idOf(req.params.id);
  if (!tokenId) return res.status(400).json({ code: "BAD_TOKEN_ID" });

  const onChain = await contracts.assets.assets(tokenId);
  if (onChain.contentHash.toLowerCase() !== String(req.body.contentHash).toLowerCase()) {
    return res.status(409).json({ code: "HASH_MISMATCH" }); // the chain is the authority
  }
  const { name, mimeType, size, contentHash, storagePath, wrappedDek } = req.body;
  await prisma.storedFile.upsert({
    where: { tokenId },
    update: {},
    create: { tokenId, name, mimeType, size, contentHash, storagePath, wrappedDek },
  });
  res.json({ ok: true });
});
router.get("/:id/content", requireAuth, async (req, res) => {
  const tokenId = idOf(req.params.id);
  if (!tokenId) return res.status(400).json({ code: "BAD_TOKEN_ID" });
  const identityId = req.user!.identityId;
  const wantsDownload = req.query.download === "1";

  const d = await authorize(req.user!, tokenId, wantsDownload ? P.DOWNLOAD : P.READ);
  if (!d.allow) {
    await logDecision({ identityId, tokenId, action: "READ", reasonCode: d.code });
    return res.status(d.status).json({ code: d.code, detail: d.detail });
  }

  const risk = await scoreRequest(identityId, tokenId);
  if (risk.score > 80) {
    await logDecision({ identityId, tokenId, action: "READ", reasonCode: "ANOMALY_SCORE_HIGH", riskScore: risk.score, reasons: risk.reasons });
    return res.status(403).json({ code: "ANOMALY_SCORE_HIGH", risk });
  }
  if (risk.score > 40 && req.headers["x-step-up"] !== "verified") {
    await logDecision({ identityId, tokenId, action: "READ", reasonCode: "STEP_UP_REQUIRED", riskScore: risk.score, reasons: risk.reasons });
    return res.status(401).json({ code: "STEP_UP_REQUIRED", risk });
  }

  const file = await prisma.storedFile.findUnique({ where: { tokenId } });
  if (!file) return res.status(404).json({ code: "FILE_NOT_STORED" });

  const plaintext = loadAndDecrypt(file.storagePath, file.wrappedDek);
  const onChainHash = (await contracts.assets.assets(tokenId)).contentHash;
  if (sha256(plaintext).toLowerCase() !== onChainHash.toLowerCase()) {
    await logDecision({ identityId, tokenId, action: "READ", reasonCode: "TAMPER_DETECTED" });
    return res.status(409).json({ code: "TAMPER_DETECTED" });
  }

  await logDecision({ identityId, tokenId, action: "READ", reasonCode: "ALLOW", riskScore: risk.score, reasons: risk.reasons });
  res.setHeader("Content-Type", file.mimeType);
  res.setHeader("X-Content-Hash", onChainHash);
  res.setHeader("X-Risk-Score", String(risk.score));
  if (wantsDownload) res.setHeader("Content-Disposition", `attachment; filename="${file.name}"`);
  res.send(plaintext);
});

export default router;