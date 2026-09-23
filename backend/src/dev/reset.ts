import "dotenv/config";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const run = (cmd: string, cwd: string) =>
  execSync(cmd, { cwd, stdio: "inherit", shell: "powershell.exe" });

const BACKEND = path.resolve(__dirname, "../..");
const ROOT = path.resolve(BACKEND, "..");

// The chain, the database and the ciphertext on disk all carry token ids.
// Resetting one without the others leaves rows pointing at the wrong asset.
fs.rmSync(path.join(BACKEND, "storage"), { recursive: true, force: true });
fs.rmSync(path.join(BACKEND, "prisma", "argus.db"), { force: true });
run("npx prisma migrate deploy", BACKEND);

run("npm run deploy:local", ROOT);
run("npm run seed:local", ROOT);

// unique content every time, so DuplicateContent can never bite
const demo = path.join(BACKEND, "demo.txt");
fs.writeFileSync(demo, `ArgusChain demo document ${new Date().toISOString()}\n`);
run(`npx ts-node src/dev/full-upload.ts ${demo}`, BACKEND);

console.log("\nreset complete: chain redeployed, seeded, demo file uploaded");