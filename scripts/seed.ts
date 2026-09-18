import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import {
  P, CLASSIFICATION, ROOT, principals, labelHash, nodeId, unitId,
  compartment, justify, empCommitment, SECURITY_OFFICER, INTERNAL_AUDITOR,
} from "./constants";

/**
 * Seeds the demo scenario from the pitch:
 *   /BEL/Ghaziabad/RADAR-X/specs.pdf  — direct grant + inherited group grant + explicit deny
 *   /BEL/Ghaziabad/RADAR-X/budget.pdf — SECRET, reachable only via four-eyes
 */
async function main() {
  const dep = JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "deployments", `${network.name}.json`), "utf8")
  );
  const c = dep.contracts;

  const identity = await ethers.getContractAt("ArgusIdentity", c.ArgusIdentity);
  const designations = await ethers.getContractAt("DesignationRegistry", c.DesignationRegistry);
  const groups = await ethers.getContractAt("GroupRegistry", c.GroupRegistry);
  const resources = await ethers.getContractAt("ResourceRegistry", c.ResourceRegistry);
  const access = await ethers.getContractAt("AccessRegistry", c.AccessRegistry);

  const signers = await ethers.getSigners();
  const GHZ = unitId("Ghaziabad");
  const BLR = unitId("Bangalore");
  const RADARX = compartment("RADAR-X");
  const now = Math.floor(Date.now() / 1000);
  const tenure = now + 5 * 365 * 24 * 3600;

  const people = [
    { key: "sharma",  emp: "EMP-4471", name: "R. Sharma",  addr: signers[2], unit: GHZ, clearance: CLASSIFICATION.SECRET,       desig: 5,  extra: [23] },
    { key: "verma",   emp: "EMP-8823", name: "A. Verma",   addr: signers[3], unit: GHZ, clearance: CLASSIFICATION.CONFIDENTIAL, desig: 7,  extra: [] },
    { key: "kumar",   emp: "EMP-1190", name: "S. Kumar",   addr: signers[4], unit: GHZ, clearance: CLASSIFICATION.CONFIDENTIAL, desig: 7,  extra: [] },
    { key: "officer", emp: "EMP-0002", name: "P. Nair",    addr: signers[5], unit: BLR, clearance: CLASSIFICATION.SECRET,       desig: 4,  extra: [SECURITY_OFFICER] },
    { key: "auditor", emp: "EMP-0003", name: "K. Rao",     addr: signers[6], unit: BLR, clearance: CLASSIFICATION.TOP_SECRET,   desig: 6,  extra: [INTERNAL_AUDITOR] },
    { key: "engg",    emp: "EMP-2250", name: "T. Iyer",    addr: signers[7], unit: BLR, clearance: CLASSIFICATION.RESTRICTED,   desig: 10, extra: [] },
  ];

  const ids: Record<string, bigint> = {};
  for (const p of people) {
    const tx = await identity.issue(
      empCommitment(p.emp, "argus-demo-salt"), p.addr.address, p.unit, ethers.ZeroHash, p.clearance, tenure
    );
    await tx.wait();
    const id = await identity.byController(p.addr.address);
    ids[p.key] = id;
    await (await designations.assign(id, p.desig)).wait();
    for (const d of p.extra) await (await designations.assign(id, d)).wait();
    console.log(`identity #${id}  ${p.name.padEnd(10)} ${p.emp}  clearance=${p.clearance}`);
  }

  await (await groups.createGroup(100, "RADAR-X Core Team", 2, RADARX)).wait();
  await (await groups.addMember(100, ids.sharma)).wait();
  await (await groups.addMember(100, ids.verma)).wait();
  await (await groups.addMember(100, ids.kumar)).wait();
  await (await groups.createGroup(200, "Ghaziabad Unit", 1, ethers.ZeroHash)).wait();
  for (const k of ["sharma", "verma", "kumar"]) await (await groups.addMember(200, ids[k])).wait();
  console.log("groups seeded");

  // ---- tree ----
  const mk = async (parent: string, label: string, type: number, cls: number, comp: string, custodian: string) => {
    await (await resources.createNode(parent, labelHash(label), type, cls, comp, custodian)).wait();
    return nodeId(parent, label);
  };
  const custodian = principals.identity(ids.sharma);

  const bel = await mk(ROOT, "BEL", 2, CLASSIFICATION.PUBLIC, ethers.ZeroHash, custodian);
  const ghz = await mk(bel, "Ghaziabad", 2, CLASSIFICATION.RESTRICTED, ethers.ZeroHash, custodian);
  const blr = await mk(bel, "Bangalore", 2, CLASSIFICATION.RESTRICTED, ethers.ZeroHash, custodian);
  const radarx = await mk(ghz, "RADAR-X", 2, CLASSIFICATION.CONFIDENTIAL, RADARX, custodian);
  const specs = await mk(radarx, "specs.pdf", 3, CLASSIFICATION.CONFIDENTIAL, ethers.ZeroHash, custodian);
  const bom = await mk(radarx, "bom.xlsx", 3, CLASSIFICATION.CONFIDENTIAL, ethers.ZeroHash, custodian);
  const budget = await mk(radarx, "budget.pdf", 3, CLASSIFICATION.SECRET, ethers.ZeroHash, custodian);
  const audit = await mk(radarx, "audit", 2, CLASSIFICATION.TOP_SECRET, ethers.ZeroHash, custodian);
  console.log("resource tree seeded");

  const perm = (...bits: number[]) => bits.reduce((a, b) => a | b, 0);

  // custodian: full admin over the subtree, inheritable
  await (await access.setAce(radarx, custodian,
    perm(P.LIST, P.READ_META, P.READ, P.DOWNLOAD, P.WRITE, P.CREATE, P.SHARE, P.ADMIN),
    0, 0, 0, true, 2, custodian, justify("Project custodian for RADAR-X"))).wait();

  // group grant, inherited — this is the "Source: <- /RADAR-X" row in the Security tab
  await (await access.setAce(radarx, principals.group(100),
    perm(P.LIST, P.READ_META, P.READ), 0, 0, 0, true, 0, custodian,
    justify("RADAR-X core team baseline read access"))).wait();

  // direct, expiring grant on one file — READ but deliberately no DOWNLOAD
  await (await access.setAce(specs, principals.identity(ids.verma),
    perm(P.READ, P.READ_META), 0, 0, now + 14 * 24 * 3600, false, 0, custodian,
    justify("Design review participation, 14 days"))).wait();

  // explicit deny — must beat the inherited group allow above
  await (await access.setAce(specs, principals.identity(ids.kumar),
    0, perm(P.READ, P.DOWNLOAD), 0, 0, false, 0, custodian,
    justify("Under investigation - access withheld pending review"))).wait();

  // auditor: metadata and history everywhere, never content
  await (await access.setAce(bel, principals.designation(INTERNAL_AUDITOR),
    perm(P.LIST, P.READ_META, P.AUDIT), P.READ | P.DOWNLOAD, 0, 0, true, 0, custodian,
    justify("Internal audit: metadata and trail only, never content"))).wait();

  console.log("ACEs seeded");

  const report = {
    identities: Object.fromEntries(Object.entries(ids).map(([k, v]) => [k, v.toString()])),
    nodes: { bel, ghz, blr, radarx, specs, bom, budget, audit },
    groups: { radarxCoreTeam: 100, ghaziabadUnit: 200 },
    wallets: Object.fromEntries(people.map((p) => [p.key, p.addr.address])),
  };
  fs.writeFileSync(
    path.join(__dirname, "..", "deployments", `${network.name}.seed.json`),
    JSON.stringify(report, null, 2)
  );

  console.log("\n--- effective access check ---");
  for (const who of ["sharma", "verma", "kumar", "engg", "auditor"]) {
    const eff = await access.effectivePermissionsForIdentity(specs, ids[who]);
    console.log(`  ${who.padEnd(8)} on specs.pdf -> 0x${Number(eff).toString(16).padStart(3, "0")}`);
  }
  console.log(`\nwritten -> deployments/${network.name}.seed.json`);
}

main().catch((e) => { console.error(e); process.exit(1); });
