import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  P, CLASSIFICATION, ROLE, principals, justify, empCommitment, contentHashOf,
  signRegister, FAR_FUTURE,
} from "./constants";

/**
 * Seeds the v4 demo scenario:
 *   - five identities across the five roles (Admin, Manager, Auditor, User,
 *     Security Officer), each registered with its own EIP-712 signature
 *   - a founding Security Officer bootstrapped at TOP_SECRET clearance, so
 *     the four-eyes workflow has an eligible approver from the start
 *   - two PUBLIC/RESTRICTED assets minted directly, one CONFIDENTIAL asset
 *     minted through GrantWorkflow (MINT_AND_ALLOCATE)
 *   - a direct RESTRICTED-tier ACE grant and a CONFIDENTIAL-tier grant
 *     through the four-eyes workflow
 *   - the resulting effective-permissions table, mirroring the "Security tab"
 *     read-out from the v3 seed script
 */
async function main() {
  const dep = JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "deployments", `${network.name}.json`), "utf8")
  );
  const c = dep.contracts;

  const identity = await ethers.getContractAt("ArgusIdentity", c.ArgusIdentity);
  const roles = await ethers.getContractAt("RoleRegistry", c.RoleRegistry);
  const assets = await ethers.getContractAt("AssetNFT", c.AssetNFT);
  const access = await ethers.getContractAt("AccessRegistry", c.AccessRegistry);
  const workflow = await ethers.getContractAt("GrantWorkflow", c.GrantWorkflow);

  const signers = await ethers.getSigners();
  const [deployer] = signers;

  const people = [
    { key: "admin",   name: "R. Sharma (Admin)",            addr: signers[0], role: ROLE.ADMIN },
    { key: "manager", name: "A. Verma (Manager)",            addr: signers[2], role: ROLE.MANAGER },
    { key: "auditor", name: "K. Rao (Auditor)",               addr: signers[3], role: ROLE.AUDITOR },
    { key: "user",    name: "S. Kumar (User)",                addr: signers[4], role: ROLE.USER },
    { key: "officer", name: "P. Nair (Security Officer)",     addr: signers[5], role: ROLE.SECURITY_OFFICER },
  ];

  const validUntil = BigInt(Math.floor(Date.now() / 1000)) + 5n * 365n * 24n * 3600n;
  const ids: Record<string, bigint> = {};

  for (let i = 0; i < people.length; i++) {
    const p = people[i];
    const emp = empCommitment(`EMP-${1000 + i}`, "argus-v4-demo-salt");
    const deadline = FAR_FUTURE;
    const nonce = await identity.nonces(p.addr.address);
    const sig = await signRegister(p.addr, identity, p.addr.address, emp, 1, validUntil, nonce, deadline);
    const tx = await identity.connect(deployer).registerIdentity(p.addr.address, emp, 1, validUntil, deadline, sig);
    await tx.wait();
    ids[p.key] = await identity.byDid(p.addr.address);
    console.log(`identity #${ids[p.key]}  ${p.name.padEnd(28)} ${p.addr.address}`);
  }

  // Grant role tokens (Admin already holds ADMIN from RoleRegistry.bootstrap()).
  for (const p of people) {
    if (p.role === ROLE.ADMIN) continue;
    await (await roles.connect(deployer).grantRoleToken(p.addr.address, p.role)).wait();
  }
  console.log("role tokens granted");

  // Bootstrap the Security Officer to TOP_SECRET clearance — otherwise no one
  // is eligible to approve the very first CONFIDENTIAL+ proposal.
  await (await identity.connect(deployer).bootstrapClearance(ids.officer, CLASSIFICATION.TOP_SECRET)).wait();
  console.log("Security Officer bootstrapped to TOP_SECRET clearance");

  // ---- assets ----
  const specsHash = contentHashOf("RADAR-X/specs.pdf v1");
  const bomHash = contentHashOf("RADAR-X/bom.xlsx v1");
  const budgetHash = contentHashOf("RADAR-X/budget.pdf v1");

  let tx = await assets.connect(deployer).mint(ids.manager, specsHash, CLASSIFICATION.PUBLIC, justify("Project spec, public release"));
  let rc = await tx.wait();
  const specsId = 1n;

  tx = await assets.connect(deployer).mint(ids.manager, bomHash, CLASSIFICATION.RESTRICTED, justify("Bill of materials, internal"));
  await tx.wait();
  const bomId = 2n;
  console.log(`minted specs.pdf (#${specsId}, PUBLIC) and bom.xlsx (#${bomId}, RESTRICTED) to manager`);

  // Manager needs CONFIDENTIAL clearance before a CONFIDENTIAL asset can be
  // allocated to them — propose, approve (Security Officer), execute.
  let pid = await workflow.connect(deployer).proposeClearanceUplift.staticCall(
    ids.manager, CLASSIFICATION.CONFIDENTIAL, justify("Manager needs budget access"), ids.admin
  );
  await (await workflow.connect(deployer).proposeClearanceUplift(
    ids.manager, CLASSIFICATION.CONFIDENTIAL, justify("Manager needs budget access"), ids.admin
  )).wait();
  await (await workflow.connect(deployer).approve(pid, ids.officer)).wait();
  await (await workflow.connect(deployer).execute(pid)).wait();
  console.log(`clearance uplift executed: manager -> CONFIDENTIAL (proposal #${pid})`);

  // Now mint budget.pdf (CONFIDENTIAL) through the workflow.
  pid = await workflow.connect(deployer).proposeMint.staticCall(
    ids.manager, budgetHash, CLASSIFICATION.CONFIDENTIAL, justify("RADAR-X budget, restricted circulation"), ids.admin
  );
  await (await workflow.connect(deployer).proposeMint(
    ids.manager, budgetHash, CLASSIFICATION.CONFIDENTIAL, justify("RADAR-X budget, restricted circulation"), ids.admin
  )).wait();
  await (await workflow.connect(deployer).approve(pid, ids.officer)).wait();
  await (await workflow.connect(deployer).execute(pid)).wait();
  const budgetId = 3n;
  console.log(`minted budget.pdf (#${budgetId}, CONFIDENTIAL) to manager via GrantWorkflow (proposal #${pid})`);

  // ---- ACEs ----
  // Direct grant: user gets read-only on specs.pdf (PUBLIC, no workflow needed).
  await (await access.connect(deployer).setAce(
    ethers.zeroPadValue(ethers.toBeHex(specsId), 32),
    principals.identity(ids.user),
    P.LIST | P.READ_META | P.READ, 0, 0, 0, 0, ids.manager,
    justify("Design review participation")
  )).wait();
  console.log("direct ACE: user -> READ on specs.pdf");

  // Workflow grant: user gets read-only on budget.pdf (CONFIDENTIAL, 1 approval).
  const budgetGrantExpiry = BigInt(Math.floor(Date.now() / 1000)) + 150n * 24n * 3600n; // within CONFIDENTIAL's 180-day maxTtl
  pid = await workflow.connect(deployer).proposeGrant.staticCall(
    budgetId, principals.identity(ids.user), P.LIST | P.READ_META | P.READ, 0,
    budgetGrantExpiry, 0, justify("Budget review, time-boxed"), ids.admin
  );
  await (await workflow.connect(deployer).proposeGrant(
    budgetId, principals.identity(ids.user), P.LIST | P.READ_META | P.READ, 0,
    budgetGrantExpiry, 0, justify("Budget review, time-boxed"), ids.admin
  )).wait();
  await (await workflow.connect(deployer).approve(pid, ids.officer)).wait();
  await (await workflow.connect(deployer).execute(pid)).wait();
  console.log(`workflow ACE: user -> READ on budget.pdf (proposal #${pid})`);

  // ---- effective access check ----
  console.log("\n--- effective access: budget.pdf (CONFIDENTIAL) ---");
  for (const who of ["admin", "manager", "auditor", "user", "officer"]) {
    const eff = await access.effectivePermissionsForIdentity(
      ethers.zeroPadValue(ethers.toBeHex(budgetId), 32), ids[who]
    );
    console.log(`  ${who.padEnd(8)} -> 0x${Number(eff).toString(16).padStart(2, "0")}`);
  }

  const report = {
    identities: Object.fromEntries(Object.entries(ids).map(([k, v]) => [k, v.toString()])),
    assets: { specs: specsId.toString(), bom: bomId.toString(), budget: budgetId.toString() },
    wallets: Object.fromEntries(people.map((p) => [p.key, p.addr.address])),
  };
  fs.writeFileSync(
    path.join(__dirname, "..", "deployments", `${network.name}.seed.json`),
    JSON.stringify(report, null, 2)
  );
  console.log(`\nwritten -> deployments/${network.name}.seed.json`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
