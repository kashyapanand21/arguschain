import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import { DESIGNATIONS } from "./constants";

async function main() {
  const [deployer, relayer] = await ethers.getSigners();
  const admin = deployer.address;
  const relayerAddr = (relayer ?? deployer).address;

  console.log(`network : ${network.name}`);
  console.log(`deployer: ${admin}`);
  console.log(`relayer : ${relayerAddr}`);

  const identity = await (await ethers.getContractFactory("ArgusIdentity")).deploy(admin);
  await identity.waitForDeployment();

  const designations = await (
    await ethers.getContractFactory("DesignationRegistry")
  ).deploy(admin, await identity.getAddress());
  await designations.waitForDeployment();

  const groups = await (await ethers.getContractFactory("GroupRegistry")).deploy(admin);
  await groups.waitForDeployment();

  const resources = await (await ethers.getContractFactory("ResourceRegistry")).deploy(admin);
  await resources.waitForDeployment();

  const access = await (
    await ethers.getContractFactory("AccessRegistry")
  ).deploy(
    admin,
    await identity.getAddress(),
    await designations.getAddress(),
    await groups.getAddress(),
    await resources.getAddress()
  );
  await access.waitForDeployment();

  const workflow = await (
    await ethers.getContractFactory("GrantWorkflow")
  ).deploy(
    admin,
    await identity.getAddress(),
    await designations.getAddress(),
    await resources.getAddress(),
    await access.getAddress()
  );
  await workflow.waitForDeployment();

  const audit = await (await ethers.getContractFactory("AuditAnchor")).deploy(admin);
  await audit.waitForDeployment();

  // ---- wiring: this is the part that silently breaks everything if missed ----
  await (await resources.setAuthorizer(await access.getAddress())).wait();
  await (
    await access.grantRole(await access.GRANT_EXECUTOR_ROLE(), await workflow.getAddress())
  ).wait();
  await (await identity.grantRole(await identity.SECURITY_OFFICER_ROLE(), admin)).wait();

  // relayer may submit transactions on a user's behalf after gateway PDP + step-up
  await (await resources.grantRole(await resources.NODE_WRITER_ROLE(), relayerAddr)).wait();
  await (await access.grantRole(await access.ACL_WRITER_ROLE(), relayerAddr)).wait();
  await (await workflow.grantRole(await workflow.RELAYER_ROLE(), relayerAddr)).wait();
  await (await audit.grantRole(await audit.ANCHOR_ROLE(), relayerAddr)).wait();

  // ---- designation ladder ----
  for (const d of DESIGNATIONS) {
    await (
      await designations.defineDesignation(d.id, d.label, d.grade, d.ceiling, d.functional)
    ).wait();
  }
  console.log(`defined ${DESIGNATIONS.length} designations`);

  const out = {
    network: network.name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    deployedAt: new Date().toISOString(),
    deployer: admin,
    relayer: relayerAddr,
    contracts: {
      ArgusIdentity: await identity.getAddress(),
      DesignationRegistry: await designations.getAddress(),
      GroupRegistry: await groups.getAddress(),
      ResourceRegistry: await resources.getAddress(),
      AccessRegistry: await access.getAddress(),
      GrantWorkflow: await workflow.getAddress(),
      AuditAnchor: await audit.getAddress(),
    },
    startBlock: await ethers.provider.getBlockNumber(),
  };

  const dir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${network.name}.json`), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out.contracts, null, 2));
  console.log(`\nwritten -> deployments/${network.name}.json`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
