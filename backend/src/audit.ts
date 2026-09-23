import crypto from "crypto";
import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient();
const GENESIS = "0x" + "0".repeat(64);

export async function logDecision(entry: {
  identityId: string; tokenId?: string; action: string;
  reasonCode: string; riskScore?: number; reasons?: string[];
}) {
  const last = await prisma.decision.findFirst({ orderBy: { id: "desc" } });
  const prevHash = last?.rowHash ?? GENESIS;
  const payload = JSON.stringify({ ...entry, prevHash, ts: Date.now() });
  const rowHash = "0x" + crypto.createHash("sha256").update(payload).digest("hex");

  return prisma.decision.create({
    data: {
      identityId: entry.identityId, tokenId: entry.tokenId ?? null,
      action: entry.action, reasonCode: entry.reasonCode,
      riskScore: entry.riskScore ?? 0, reasons: JSON.stringify(entry.reasons ?? []),
      prevHash, rowHash,
    },
  });
}