# ArgusChain v4 — Contracts

Solidity layer for SIH26125, built against the v4 Final Architecture
Specification (DID-anchored identity, NFT-native assets, role tokens with
per-asset access control). This is a from-scratch v4 implementation, using
the v3 contracts as a structural starting point where the two designs agree
(the ACE resolution model, the propose/approve/execute workflow shape, the
setAce/executeGrant dual-path pattern).

## Status

Compiles on solc 0.8.24 (EVM target: cancun). **28/28 tests passing**,
covering every invariant in Section 11.2 that still applies to v4's flatter
resource model, plus DID auth, RBAC, four-eyes, break-glass, and audit
anchoring. Verified end-to-end (bootstrap → register → role grants →
PUBLIC/RESTRICTED direct mint → CONFIDENTIAL mint via workflow → direct and
workflow ACE grants → effective-permissions read-out) against a local
Hardhat node. Not deployed to Sepolia — no RPC access from this environment.

## Quick start

```bash
npm install
npx hardhat compile
npx hardhat test

# local end-to-end
npx hardhat node               # terminal 1
npm run deploy:local           # terminal 2
npm run seed:local
```

For Sepolia, copy `.env.example` to `.env`, fill in `SEPOLIA_RPC_URL` and
`DEPLOYER_PRIVATE_KEY`, then `npm run deploy:sepolia`.

### Note on the compiler

Same offline-build workaround as v3: `hardhat.config.ts` points
`TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD` at the npm `solc` package instead of
downloading a native binary from `binaries.soliditylang.org`, which was
unreachable from this build environment.

## Contract inventory

| Contract | Standard | Responsibility |
|---|---|---|
| `EthereumDIDRegistry` | ERC-1056 (local reference copy) | did:ethr identity/owner mapping. Deploy the canonical registry for a real network instead — ArgusIdentity only calls `identityOwner()`. |
| `ArgusIdentity` | ERC-721 + ERC-5192 | Soulbound identity credential: clearance, status, tenure, uniqueness. |
| `RoleRegistry` | ERC-1155, non-transferable | The four PS roles (Admin, Manager, Auditor, User) + Security Officer. |
| `AssetNFT` | ERC-721, controlled transfer | Digital assets: admin-gated mint, unique content hash, no ordinary transfer. |
| `AccessRegistry` | purpose-built | ACEs, `effectivePermissionsForIdentity()` — the Figure 2 resolver. |
| `GrantWorkflow` | purpose-built | propose/approve/execute across every privileged action, with separation of duty. |
| `AuditAnchor` | purpose-built | Merkle roots of batched off-chain decision-log lines, incident records. |

Libraries: `Permissions` (the 8-bit mask, Section 5.4), `Principals` (one
`bytes32` for IDENTITY or ROLE — GROUP/UNIT are Tier 3, not built here).

## Invariants, as executable tests

| Invariant | Test |
|---|---|
| INV-1 (adapted) | clearance below classification never yields `P_READ`, even when an ACE over-grants it |
| INV-2 | revoking an identity zeroes access everywhere |
| INV-3 | a deny bit always wins over an allow |
| INV-4 | identity and role tokens never transfer (soulbound / non-transferable) |
| INV-7 | proposer cannot approve their own proposal |
| INV-8 | Auditor and Security Officer never hold content bits, no matter what an ACE grants |

v3's INV-5 (no SECRET+ ACE outside the workflow) and INV-6 (classification
monotonicity down a tree) don't carry over as-is: v4 has no namehash
resource tree (Tier 3), so there's no parent/child classification to keep
monotonic, and the CONFIDENTIAL+ boundary — not SECRET+ — is where v4 draws
the direct-write-vs-workflow line (see below). Both are re-tested at their
new boundary: `setAce`/`mint`/`controlledTransfer` all revert
`RequiresWorkflow` at CONFIDENTIAL and above.

## Two decisions the spec leaves implicit, made explicit here

1. **`P_ADMIN` is seeded to the Admin *role*, not to an owner or a specific
   minting Admin's identity.** Section 6.1 says the owner's default ACE is
   `P_LIST|P_READ_META|P_READ|P_DOWNLOAD|P_WRITE|P_SHARE` and that "the Admin
   who minted it receives none of the content bits" — implying the Admin
   *does* receive something. Without that something, a freshly minted
   CONFIDENTIAL+ asset would have no one able to administer its ACL at all:
   `proposeGrant`/`proposeTransfer` both require the proposer to already hold
   `P_ADMIN`, and the owner's own default ACE doesn't include it. `AssetNFT`
   seeds `P_LIST|P_ADMIN` to the `ADMIN` role principal on every mint, and
   `AccessRegistry._applyRoleRules` restores those two bits for any Admin
   role-holder *after* the MAC gate — administering an ACL never exposes
   content, so an Admin's own clearance is not a reason to block it. This is
   what makes "Admin grants but cannot read" (Section 5.3) hold structurally:
   Admin gets exactly `P_LIST|P_ADMIN` for free, never a content bit, on
   every asset, regardless of their personal clearance.

2. **A founding committee needs to be seeded directly.** The four-eyes
   `CLEARANCE_UPLIFT` path requires an approver who already holds the target
   clearance — including, for SECRET/TOP_SECRET, *two* such approvers, one a
   Security Officer. Nobody can reach CONFIDENTIAL+ through
   `registerIdentity` alone (it refuses anything above RESTRICTED directly),
   so the first CONFIDENTIAL+ proposal would otherwise have no eligible
   approver. `ArgusIdentity.bootstrapClearance(id, clearance)` is a
   `DEFAULT_ADMIN_ROLE`-gated escape hatch, meant to be called a handful of
   times during setup to seed a small founding committee (the seed script and
   tests use two TOP_SECRET Security Officers), then never again — the
   deployer renounces `DEFAULT_ADMIN_ROLE` once the committee exists, exactly
   as `RoleRegistry.bootstrap()` already expects for the first Admin.

## Design notes worth defending

- **DID resolution is split into two mappings, deliberately.** `byDid` maps
  a DID address to its identityId — stable forever, set once at
  registration. `byController` maps the *current* controlling key to the
  same identityId, and is the one every address-keyed authorization check
  actually reads (`AccessRegistry.effectivePermissions(resourceId, address)`,
  `GrantWorkflow`'s direct-caller path). The reason for two mappings: the
  ERC-1056 registry's `changeOwner` can only be called *by* the current
  owner, so `ArgusIdentity` — which is not that owner — cannot intercept a
  rotation and update anything atomically. `syncController(id)` is a
  permissionless, idempotent catch-up call: rotate on the registry directly
  (Section 4.5), then call `syncController` once (or let the gateway call it
  on session start) before address-keyed lookups need to be correct again.
  Identity-keyed calls (`effectivePermissionsForIdentity`, `controllerOf`)
  never need this — they read `identityOwner()` live on every call, so they
  are correct even mid-rotation, which is what makes key rotation
  grant-preserving in the first place (Section 4.5's actual claim).
- **Why a registry, not a badge per (user, asset).** Unchanged from v3's
  argument, restated for v4's token set: an ERC-1155 role balance can't
  express read-but-not-download, can't expire, and can't deny. Identity,
  roles and assets are tokens because uniqueness/possession is the right
  question for them; per-asset permissions are not, so they live in
  `AccessRegistry`.
- **`resourceId = bytes32(tokenId)` today, on purpose.** Section 13.2's
  extension path swaps this for a namehash folder-tree node id without
  touching the `Ace` struct, the workflow, or the audit events — `AssetNFT`
  and `AccessRegistry` never assume the resourceId *is* a token id beyond
  the one conversion function, `AssetNFT.resourceIdOf()`.
- **One unified propose/approve/execute path.** `GRANT`, `MINT_AND_ALLOCATE`,
  `TRANSFER`, `CLEARANCE_UPLIFT` and `ADMIN_ROLE_MINT` all flow through the
  same `Proposal` struct and the same per-tier `Policy` (approvals required,
  Security-Officer requirement, timelock, max TTL), dispatched in
  `GrantWorkflow._dispatch`. Minting a second Admin is judged at the
  TOP_SECRET tier — the most powerful role gets the strictest gate.
- **`justificationHash` is mandatory** on every ACE write, exactly as in v3:
  `_writeAce` reverts on a zero hash, so a permanent, hash-committed written
  reason exists for every grant, forever.
- **Break-glass is gated by the Security Officer role token, not an
  operational AccessControl role.** An earlier draft gated `breakGlass` by
  `onlyRole(WORKFLOW_ADMIN_ROLE)` *and* required the resolved actor to be a
  Security Officer — but those two checks can't both pass for a plain SO
  wallet that doesn't also hold the operational key. Fixed to resolve the
  caller's own identity and check the SO role token directly, matching how
  `ArgusIdentity.suspend`/`revoke` already gate on the role token rather than
  a parallel permission system.

## What this build does not include (Tier 2 / Tier 3, by the spec's own scope)

- Sepolia deployment or Etherscan verification — no RPC access here.
- Foundry invariant fuzzing or Slither — not run in this environment; the
  invariants above exist as Hardhat unit tests only.
- Timelocked break-glass auto-expiry beyond the on-chain `expiresAt` cap —
  the P1 alert and off-chain enforcement are outside the contract layer.
- The gateway (SIWE session issuance, PDP/PEP, Vault envelope encryption,
  Postgres mirror), the AI/UEBA service, and MinIO storage — all Section 3
  layers above the chain, not part of this Solidity chunk.
- GROUP/UNIT principals and the namehash resource tree — Tier 3 per the
  spec's own traceability table (Appendix A); `Principals.PrincipalType` has
  room for them without a migration.

## Next

The gateway (NestJS/Express + viem, per Section 3.3): SIWE auth, the PDP/PEP
split, the chain indexer and Postgres mirror, and Vault-backed envelope
encryption for file storage.
