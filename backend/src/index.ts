import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

import authRoutes from "./controllers/auth";
import fileRoutes from "./controllers/files";
import { BlockchainIndexer } from "./indexer/index";

// Routes
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.use("/auth", authRoutes);
app.use("/files", fileRoutes);

app.listen(PORT, () => {
  console.log(`[PEP API] ArgusChain v4 backend running on http://localhost:${PORT}`);
  const indexer = new BlockchainIndexer();
  indexer.start();
});
