import { prisma } from "./audit";

export interface Risk { score: number; reasons: string[] }

export async function scoreRequest(identityId: string, tokenId: string): Promise<Risk> {
  const reasons: string[] = [];
  let score = 0;

  const hour = new Date().getHours();
  if (hour >= 22 || hour < 6) { score += 30; reasons.push(`Access at ${hour}:00, outside working hours`); }

  const since = new Date(Date.now() - 5 * 60 * 1000);
  const recent = await prisma.decision.findMany({
    where: { identityId, ts: { gte: since }, action: "READ" },
  });
  const distinct = new Set(recent.map((r) => r.tokenId)).size;
  if (distinct >= 3) { score += 40; reasons.push(`${distinct} distinct assets in 5 minutes against a baseline of 1`); }

  const denials = await prisma.decision.count({
    where: { identityId, ts: { gte: since }, reasonCode: { not: "ALLOW" } },
  });
  if (denials >= 3) { score += 30; reasons.push(`${denials} denials in 5 minutes: probing pattern`); }

  const firstTime = !(await prisma.decision.findFirst({
    where: { identityId, tokenId, reasonCode: "ALLOW" },
  }));
  if (firstTime) { score += 15; reasons.push("First-ever access to this asset"); }

  return { score: Math.min(score, 100), reasons };
}