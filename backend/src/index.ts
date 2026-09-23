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
import { contracts, provider } from "./chain";

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

app.use("/auth", authRoutes);
app.use("/assets", assetRoutes);
app.use("/audit", auditRoutes);

app.listen(PORT, () => {
  console.log(`[PEP API] ArgusChain v4 backend running on http://localhost:${PORT}`);
});
