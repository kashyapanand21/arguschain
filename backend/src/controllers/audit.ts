import { Router } from "express";
import { contracts, startBlock } from "../chain";
import { requireAuth } from "../middleware/auth";
import { prisma } from "../audit";
import { ROLE } from "../constants";

const router = Router();

router.get("/:tokenId", requireAuth, async (req, res) => {
  const tokenId = String(req.params.tokenId);
  const isAuditor = req.user!.roles.some((r) => r === ROLE.AUDITOR || r === ROLE.SECURITY_OFFICER);

  const resourceId = "0x" + BigInt(tokenId).toString(16).padStart(64, "0");
  const [minted, aces, transfers] = await Promise.all([
    contracts.assets.queryFilter(contracts.assets.filters.AssetMinted(tokenId), startBlock),
    contracts.access.queryFilter(contracts.access.filters.AceSet(resourceId), startBlock),
    contracts.assets.queryFilter(contracts.assets.filters.AssetTransferred(tokenId), startBlock),
  ]);

  const onChain = [...minted, ...aces, ...transfers].map((e: any) => ({
    type: e.fragment.name, txHash: e.transactionHash, block: e.blockNumber,
    args: Object.fromEntries(Object.entries(e.args.toObject()).map(([k, v]) => [k, String(v)])),
  }));

  const decisions = await prisma.decision.findMany({
    where: { tokenId, ...(isAuditor ? {} : { identityId: req.user!.identityId }) },
    orderBy: { id: "desc" }, take: 100,
  });

  res.json({ onChain, decisions: decisions.map((d) => ({ ...d, reasons: JSON.parse(d.reasons) })) });
});

export default router;