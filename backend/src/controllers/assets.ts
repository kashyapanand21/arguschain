import { Router } from "express";
import { contracts } from "../chain";
import { requireAuth } from "../middleware/auth";
import { authorize } from "../pdp";
import { P } from "../constants";

const router = Router();

const BITS: [string, number][] = [
  ["P_LIST", P.LIST], ["P_READ_META", P.READ_META], ["P_READ", P.READ],
  ["P_DOWNLOAD", P.DOWNLOAD], ["P_WRITE", P.WRITE], ["P_SHARE", P.SHARE],
  ["P_ADMIN", P.ADMIN], ["P_AUDIT", P.AUDIT],
];

router.get("/:id/effective", requireAuth, async (req, res) => {
  const tokenId = String(req.params.id);
  if (!/^\d+$/.test(tokenId)) return res.status(400).json({ code: "BAD_TOKEN_ID" });

  const decision = await authorize(req.user!, tokenId, P.LIST);
  const classification = Number(await contracts.assets.classificationOf(tokenId));
  res.json({
      tokenId,
      identityId: req.user!.identityId,
    clearance: req.user!.clearance,
    classification,
    effective: `0x${decision.effective.toString(16).padStart(2, "0")}`,
    bits: BITS.map(([name, bit]) => ({ name, granted: (decision.effective & bit) !== 0 })),
  });
});

export default router;