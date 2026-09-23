import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

import authRoutes from "./controllers/auth";
import assetRoutes from "./controllers/assets";
import auditRoutes from "./controllers/audit";
import { contracts, provider, addresses } from "./chain";
import { prisma } from "./audit";
import { requireAuth } from "./middleware/auth";

// Routes
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.get("/health/chain", async (_req, res) => {
  const [block, minted, issued] = await Promise.all([
    provider.getBlockNumber(),
    contracts.assets.totalMinted(),
    contracts.identity.totalIssued(),
  ]);
  res.json({ block, assets: Number(minted), identities: Number(issued) });
});
// The browser signs its own mint transactions, so it needs the addresses.
// Addresses are public on chain; no secret leaves the server here.
app.get("/config", (_req, res) => res.json({ contracts: addresses, chainId: 31337 }));

app.get("/decisions", requireAuth, async (_req, res) => {
  const rows = await prisma.decision.findMany({ orderBy: { id: "desc" }, take: 100 });
  res.json(rows.map((d) => ({ ...d, reasons: JSON.parse(d.reasons) })));
});

app.use("/auth", authRoutes);
app.use("/assets", assetRoutes);
app.use("/audit", auditRoutes);

app.listen(PORT, () => {
  console.log(`[PEP API] ArgusChain v4 backend running on http://localhost:${PORT}`);
});
