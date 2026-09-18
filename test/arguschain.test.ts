import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import {
  P, CLASSIFICATION, ROOT, principals, labelHash, nodeId, pathToNodeId,
  unitId, compartment, justify, empCommitment, DESIGNATIONS, SECURITY_OFFICER,
} from "../scripts/constants";

const GHAZIABAD = unitId("Ghaziabad");
const BANGALORE = unitId("Bangalore");
const RADARX = compartment("RADAR-X");
const FOREVER = 0n;
const YEAR = 365n * 24n * 60n * 60n;

async function deployFixture() {
  const [admin, alice, bob, carol, dave, mallory] = await ethers.getSigners();

  const identity = await (await ethers.getContractFactory("ArgusIdentity")).deploy(admin.address);
  const designations = await (await ethers.getContractFactory("DesignationRegistry"))
    .deploy(admin.address, await identity.getAddress());
  const groups = await (await ethers.getContractFactory("GroupRegistry")).deploy(admin.address);
  const resources = await (await ethers.getContractFactory("ResourceRegistry")).deploy(admin.address);
  const access = await (await ethers.getContractFactory("AccessRegistry")).deploy(
    admin.address,
    await identity.getAddress(),
    await designations.getAddress(),
    await groups.getAddress(),
    await resources.getAddress()
  );
  const workflow = await (await ethers.getContractFactory("GrantWorkflow")).deploy(
    admin.address,
    await identity.getAddress(),
    await designations.getAddress(),
    await resources.getAddress(),
    await access.getAddress()
  );
  const audit = await (await ethers.getContractFactory("AuditAnchor")).deploy(admin.address);

  await resources.setAuthorizer(await access.getAddress());
  await access.grantRole(await access.GRANT_EXECUTOR_ROLE(), await workflow.getAddress());
  await identity.grantRole(await identity.SECURITY_OFFICER_ROLE(), admin.address);
  await workflow.grantRole(await workflow.RELAYER_ROLE(), admin.address);

  for (const d of DESIGNATIONS) {
    await designations.defineDesignation(d.id, d.label, d.grade, d.ceiling, d.functional);
  }

  const now = BigInt(await time.latest());
  const validUntil = now + 10n * YEAR;

  // alice: DGM Ghaziabad, SECRET clearance, custodian of RADAR-X
  await identity.issue(empCommitment("EMP-4471", "s1"), alice.address, GHAZIABAD, ethers.ZeroHash, CLASSIFICATION.SECRET, validUntil);
  // bob: Manager Ghaziabad, CONFIDENTIAL clearance
  await identity.issue(empCommitment("EMP-8823", "s2"), bob.address, GHAZIABAD, ethers.ZeroHash, CLASSIFICATION.CONFIDENTIAL, validUntil);
  // carol: Security Officer, Bangalore, SECRET
  await identity.issue(empCommitment("EMP-1190", "s3"), carol.address, BANGALORE, ethers.ZeroHash, CLASSIFICATION.SECRET, validUntil);
  // dave: Engineer Bangalore, RESTRICTED
  await identity.issue(empCommitment("EMP-2250", "s4"), dave.address, BANGALORE, ethers.ZeroHash, CLASSIFICATION.RESTRICTED, validUntil);

  const ID = { alice: 1n, bob: 2n, carol: 3n, dave: 4n };

  await designations.assign(ID.alice, 5);  // Deputy General Manager, grade 6
  await designations.assign(ID.bob, 7);    // Manager, grade 4
  await designations.assign(ID.carol, 4);  // General Manager, grade 7
  await designations.assign(ID.carol, SECURITY_OFFICER);
  await designations.assign(ID.dave, 10);  // Engineer, grade 1

  // groups: RADAR-X core team carries the need-to-know compartment
  await groups.createGroup(100, "RADAR-X Core Team", 2, RADARX);
  await groups.addMember(100, ID.alice);
  await groups.addMember(100, ID.bob);

  // tree: /BEL/Ghaziabad/RADAR-X/specs.pdf
  await resources.createNode(ROOT, labelHash("BEL"), 2, CLASSIFICATION.PUBLIC, ethers.ZeroHash, principals.identity(ID.alice));
  const bel = nodeId(ROOT, "BEL");
  await resources.createNode(bel, labelHash("Ghaziabad"), 2, CLASSIFICATION.RESTRICTED, ethers.ZeroHash, principals.identity(ID.alice));
  const ghz = nodeId(bel, "Ghaziabad");
  await resources.createNode(ghz, labelHash("RADAR-X"), 2, CLASSIFICATION.CONFIDENTIAL, RADARX, principals.identity(ID.alice));
  const radarx = nodeId(ghz, "RADAR-X");
  await resources.createNode(radarx, labelHash("specs.pdf"), 3, CLASSIFICATION.CONFIDENTIAL, ethers.ZeroHash, principals.identity(ID.alice));
  const specs = nodeId(radarx, "specs.pdf");
  await resources.createNode(radarx, labelHash("secret.pdf"), 3, CLASSIFICATION.SECRET, ethers.ZeroHash, principals.identity(ID.alice));
  const secret = nodeId(radarx, "secret.pdf");

  return {
    admin, alice, bob, carol, dave, mallory, ID,
    identity, designations, groups, resources, access, workflow, audit,
    nodes: { bel, ghz, radarx, specs, secret },
  };
}

describe("ArgusChain v3 — contracts", () => {
  describe("namehash tree", () => {
    it("folds a path to the same id the contract computes", async () => {
      const f = await deployFixture();
      expect(pathToNodeId("/BEL/Ghaziabad/RADAR-X/specs.pdf")).to.equal(f.nodes.specs);
      expect(await f.resources.nodeId(f.nodes.radarx, labelHash("specs.pdf"))).to.equal(f.nodes.specs);
    });

    it("inherits the parent compartment when none is given", async () => {
      const f = await deployFixture();
      expect(await f.resources.compartmentOf(f.nodes.specs)).to.equal(RADARX);
    });
  });

  describe("identity uniqueness", () => {
    it("rejects a second registration for the same employee", async () => {
      const f = await deployFixture();
      await expect(
        f.identity.issue(empCommitment("EMP-4471", "s1"), f.mallory.address, GHAZIABAD, ethers.ZeroHash, 1, 0)
      ).to.be.revertedWithCustomError(f.identity, "DuplicateEmployee");
    });

    it("rejects binding a wallet already bound elsewhere", async () => {
      const f = await deployFixture();
      await expect(
        f.identity.issue(empCommitment("EMP-9999", "s9"), f.alice.address, GHAZIABAD, ethers.ZeroHash, 1, 0)
      ).to.be.revertedWithCustomError(f.identity, "WalletAlreadyBound");
    });

    it("INV-4: identity tokens never transfer", async () => {
      const f = await deployFixture();
      await expect(
        f.identity.connect(f.alice).transferFrom(f.alice.address, f.mallory.address, f.ID.alice)
      ).to.be.revertedWithCustomError(f.identity, "Soulbound");
    });

    it("key rotation preserves every grant", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.alice),
        P.READ | P.LIST, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("owner"));

      expect(await f.access.effectivePermissions(f.nodes.specs, f.alice.address)).to.not.equal(0);

      const nonce = await f.identity.rotationNonce(f.ID.alice);
      const digest = ethers.solidityPackedKeccak256(
        ["uint256", "address", "uint256", "address", "uint256"],
        [(await ethers.provider.getNetwork()).chainId, await f.identity.getAddress(), f.ID.alice, f.mallory.address, nonce]
      );
      const sig = await f.mallory.signMessage(ethers.getBytes(digest));
      await f.identity.connect(f.alice).rotateController(f.ID.alice, f.mallory.address, sig);

      // old key resolves to nothing, new key inherits the entire ACL position
      expect(await f.access.effectivePermissions(f.nodes.specs, f.alice.address)).to.equal(0);
      const eff = await f.access.effectivePermissions(f.nodes.specs, f.mallory.address);
      expect(Number(eff) & P.READ).to.equal(P.READ);
    });
  });

  describe("resolution", () => {
    it("inherits an inheritable ACE down the tree", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.radarx, principals.group(100),
        P.LIST | P.READ_META | P.READ, 0, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("team"));
      const eff = Number(await f.access.effectivePermissions(f.nodes.specs, f.bob.address));
      expect(eff & P.READ).to.equal(P.READ);
    });

    it("does not inherit a non-inheritable ACE", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.radarx, principals.group(100),
        P.READ, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("local only"));
      expect(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)).to.equal(0);
    });

    it("INV-3: a deny bit anywhere in the ancestor chain always wins", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ | P.LIST, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("direct grant"));
      // deny placed three levels up on a designation the user holds
      await f.access.setAce(f.nodes.ghz, principals.designation(7),
        0, P.READ, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("managers may not read"));

      const eff = Number(await f.access.effectivePermissions(f.nodes.specs, f.bob.address));
      expect(eff & P.READ).to.equal(0);
      expect(eff & P.LIST).to.equal(P.LIST); // only the denied bit dies
    });

    it("stops the walk at an inheritance break", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.ghz, principals.group(100),
        P.READ, 0, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("unit grant"));
      expect(Number(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)) & P.READ).to.equal(P.READ);

      await f.resources.setInheritance(f.nodes.radarx, false);
      expect(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)).to.equal(0);
    });

    it("honours notBefore and expiresAt", async () => {
      const f = await deployFixture();
      const now = BigInt(await time.latest());
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ, 0, now + 1000n, now + 2000n, false, 0, principals.identity(f.ID.alice), justify("window"));

      expect(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)).to.equal(0);
      await time.increaseTo(now + 1500n);
      expect(Number(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)) & P.READ).to.equal(P.READ);
      await time.increaseTo(now + 2500n);
      expect(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)).to.equal(0);
    });

    it("INV-1: clearance below classification never yields P_READ", async () => {
      const f = await deployFixture();
      // dave is RESTRICTED; secret.pdf is SECRET. Grant him everything anyway.
      await f.access.setAce(f.nodes.radarx, principals.identity(f.ID.dave),
        P.LIST | P.READ_META | P.READ | P.DOWNLOAD, 0, 0, FOREVER, true, 0,
        principals.identity(f.ID.alice), justify("over-granted on purpose"));

      const eff = Number(await f.access.effectivePermissions(f.nodes.secret, f.dave.address));
      expect(eff & P.READ).to.equal(0);
      expect(eff & P.DOWNLOAD).to.equal(0);
    });

    it("compartment mismatch degrades to metadata-only", async () => {
      const f = await deployFixture();
      // dave has the clearance for a CONFIDENTIAL node but is not in RADAR-X
      await f.identity.setClearance(f.ID.dave, CLASSIFICATION.CONFIDENTIAL);
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.dave),
        P.LIST | P.READ_META | P.READ, 0, 0, FOREVER, false, 0,
        principals.identity(f.ID.alice), justify("no need-to-know"));

      const eff = Number(await f.access.effectivePermissions(f.nodes.specs, f.dave.address));
      expect(eff & P.READ).to.equal(0);
      expect(eff & P.LIST).to.equal(P.LIST);       // existence stays visible
      expect(eff & P.READ_META).to.equal(P.READ_META);
    });

    it("INV-2: revoking an identity zeroes access everywhere", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ | P.LIST, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("grant"));
      expect(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)).to.not.equal(0);

      await f.identity.revoke(f.ID.bob);
      expect(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)).to.equal(0);
      expect(await f.access.effectivePermissionsForIdentity(f.nodes.specs, f.ID.bob)).to.equal(0);
    });

    it("suspension immediately zeroes access", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("grant"));
      await f.identity.suspend(f.ID.bob);
      expect(await f.access.effectivePermissions(f.nodes.specs, f.bob.address)).to.equal(0);
    });
  });

  describe("classification monotonicity", () => {
    it("INV-6: a child is never classified below its parent", async () => {
      const f = await deployFixture();
      await expect(
        f.resources.createNode(f.nodes.radarx, labelHash("public.txt"), 3, CLASSIFICATION.PUBLIC, ethers.ZeroHash, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(f.resources, "ClassificationDecrease");
    });

    it("blocks lowering a folder below its own children", async () => {
      const f = await deployFixture();
      await expect(
        f.resources.setClassification(f.nodes.radarx, CLASSIFICATION.PUBLIC)
      ).to.be.revertedWithCustomError(f.resources, "ClassificationDecrease");
    });
  });

  describe("four-eyes workflow", () => {
    it("INV-5: no SECRET+ ACE can be written outside the workflow", async () => {
      const f = await deployFixture();
      await expect(
        f.access.setAce(f.nodes.secret, principals.identity(f.ID.bob),
          P.READ, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("sneaky"))
      ).to.be.revertedWithCustomError(f.access, "FourEyesRequired");
    });

    it("INV-7: proposer cannot be the approver", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.radarx, principals.identity(f.ID.alice),
        P.ADMIN, 0, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("custodian"));

      const expiry = BigInt(await time.latest()) + 30n * 24n * 60n * 60n;
      await f.workflow.propose(f.nodes.secret, principals.identity(f.ID.bob),
        P.READ, 0, expiry, false, 0, justify("review"), f.ID.alice);

      await expect(f.workflow.approve(1, f.ID.alice))
        .to.be.revertedWithCustomError(f.workflow, "ProposerIsApprover");
    });

    it("requires a Security Officer and a different org unit for SECRET", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.radarx, principals.identity(f.ID.alice),
        P.ADMIN, 0, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("custodian"));
      const expiry = BigInt(await time.latest()) + 30n * 24n * 60n * 60n;
      await f.workflow.propose(f.nodes.secret, principals.identity(f.ID.bob),
        P.READ, 0, expiry, false, 0, justify("review"), f.ID.alice);

      // bob is in the same unit as the proposer
      await expect(f.workflow.approve(1, f.ID.bob))
        .to.be.revertedWithCustomError(f.workflow, "SameOrgUnit");
    });

    it("executes only after two approvers and the timelock", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.radarx, principals.identity(f.ID.alice),
        P.ADMIN, 0, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("custodian"));
      await f.identity.setClearance(f.ID.bob, CLASSIFICATION.SECRET);

      const expiry = BigInt(await time.latest()) + 30n * 24n * 60n * 60n;
      await f.workflow.propose(f.nodes.secret, principals.identity(f.ID.bob),
        P.READ | P.LIST, 0, expiry, false, 0, justify("design review"), f.ID.alice);

      await f.workflow.approve(1, f.ID.carol); // Security Officer, Bangalore
      await expect(f.workflow.execute(1)).to.be.revertedWithCustomError(f.workflow, "InsufficientApprovals");

      await f.workflow.approve(1, f.ID.dave); // second distinct identity, Bangalore
      await expect(f.workflow.execute(1)).to.be.revertedWithCustomError(f.workflow, "NotReady");

      await time.increase(3601);
      await f.workflow.execute(1);

      const eff = Number(await f.access.effectivePermissions(f.nodes.secret, f.bob.address));
      expect(eff & P.READ).to.equal(P.READ);
    });

    it("refuses a permanent SECRET grant", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.radarx, principals.identity(f.ID.alice),
        P.ADMIN, 0, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("custodian"));
      await expect(
        f.workflow.propose(f.nodes.secret, principals.identity(f.ID.bob),
          P.READ, 0, 0, false, 0, justify("forever"), f.ID.alice)
      ).to.be.revertedWithCustomError(f.workflow, "TtlRequired");
    });

    it("refuses a TTL beyond the classification ceiling", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.radarx, principals.identity(f.ID.alice),
        P.ADMIN, 0, 0, FOREVER, true, 0, principals.identity(f.ID.alice), justify("custodian"));
      const tooLong = BigInt(await time.latest()) + 200n * 24n * 60n * 60n; // > 90d
      await expect(
        f.workflow.propose(f.nodes.secret, principals.identity(f.ID.bob),
          P.READ, 0, tooLong, false, 0, justify("too long"), f.ID.alice)
      ).to.be.revertedWithCustomError(f.workflow, "TtlTooLong");
    });

    it("refuses a proposal from someone without P_ADMIN on the node", async () => {
      const f = await deployFixture();
      const expiry = BigInt(await time.latest()) + 30n * 24n * 60n * 60n;
      await expect(
        f.workflow.propose(f.nodes.secret, principals.identity(f.ID.bob),
          P.READ, 0, expiry, false, 0, justify("no standing"), f.ID.dave)
      ).to.be.revertedWithCustomError(f.workflow, "NoAdminOnNode");
    });
  });

  describe("delegation", () => {
    it("INV-8: delegated permissions never exceed the delegator's", async () => {
      const f = await deployFixture();
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ | P.LIST | P.SHARE, 0, 0, FOREVER, false, 2,
        principals.identity(f.ID.alice), justify("sharer"));

      await expect(
        f.access.connect(f.bob).delegate(f.nodes.specs, principals.identity(f.ID.dave),
          P.READ | P.DOWNLOAD, 0, justify("over-delegate"))
      ).to.be.revertedWithCustomError(f.access, "DelegationExceedsGrantor");
    });

    it("decrements delegation depth and terminates at zero", async () => {
      const f = await deployFixture();
      // the delegate must clear MAC on the node before P_SHARE can be exercised
      await f.identity.setClearance(f.ID.dave, CLASSIFICATION.CONFIDENTIAL);
      await f.groups.addMember(100, f.ID.dave);
      await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ | P.SHARE, 0, 0, FOREVER, false, 1, principals.identity(f.ID.alice), justify("sharer"));

      await f.access.connect(f.bob).delegate(f.nodes.specs, principals.identity(f.ID.dave),
        P.READ | P.SHARE, 0, justify("one hop"));

      const ace = await f.access.getAce(f.nodes.specs, principals.identity(f.ID.dave));
      expect(ace.delegationDepth).to.equal(0);

      await expect(
        f.access.connect(f.dave).delegate(f.nodes.specs, principals.identity(f.ID.carol),
          P.READ, 0, justify("second hop"))
      ).to.be.revertedWithCustomError(f.access, "DelegationDepthExhausted");
    });
  });

  describe("audit anchoring", () => {
    it("verifies a log line against an anchored batch root", async () => {
      const f = await deployFixture();
      const a = ethers.keccak256(ethers.toUtf8Bytes("line-a"));
      const b = ethers.keccak256(ethers.toUtf8Bytes("line-b"));
      const [lo, hi] = a <= b ? [a, b] : [b, a];
      const root = ethers.keccak256(ethers.concat([lo, hi]));

      await f.audit.anchor(root, 1, 2);
      expect(await f.audit.verify(1, a, [b])).to.equal(true);
      expect(await f.audit.verify(1, ethers.keccak256(ethers.toUtf8Bytes("forged")), [b])).to.equal(false);
    });

    it("chains batches together", async () => {
      const f = await deployFixture();
      const r1 = ethers.keccak256(ethers.toUtf8Bytes("r1"));
      const r2 = ethers.keccak256(ethers.toUtf8Bytes("r2"));
      await f.audit.anchor(r1, 1, 100);
      await f.audit.anchor(r2, 101, 200);
      const batch2 = await f.audit.batches(2);
      expect(batch2.prevRoot).to.equal(r1);
    });
  });

  describe("gas", () => {
    it("reports first-write and update gas for a grant", async () => {
      const f = await deployFixture();
      const tx = await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ | P.LIST, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("gas check"));
      const first = (await tx.wait())!.gasUsed;

      const tx2 = await f.access.setAce(f.nodes.specs, principals.identity(f.ID.bob),
        P.READ | P.LIST | P.READ_META, 0, 0, FOREVER, false, 0, principals.identity(f.ID.alice), justify("gas check 2"));
      const update = (await tx2.wait())!.gasUsed;

      console.log(`      grant gas: first write ${first}, update ${update}`);
      // The spec's 55-90k estimate holds for updating an existing ACE. A first
      // write to a fresh (node, principal) pair costs four cold SSTOREs plus the
      // enumerable push - budget ~175k and batch group grants at onboarding.
      expect(Number(first)).to.be.lessThan(180_000);
      expect(Number(update)).to.be.lessThan(90_000);
    });
  });
});
