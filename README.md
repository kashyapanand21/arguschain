# ArgusChain v3 — Contracts (Chunk 1 of 5)

Solidity layer for SIH26125. Per-identity, per-resource access control on a
hierarchical namespace, with separation of duty and four-eyes grants.

## Status

Compiles on solc 0.8.24 (EVM target: cancun). **29/29 tests passing**, including
all eight invariants from the architecture spec. Deployed and seeded successfully
against a local Hardhat node. Not yet deployed to Sepolia — see *What I could not
verify* below.

## Quick start (Windows / PowerShell or Git Bash)

```bash
cd contracts
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

`hardhat.config.ts` contains a `TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD` override
that points at the npm `solc` package instead of downloading a native binary from
`binaries.soliditylang.org`. That host was unreachable from the build environment.
It works identically; if you would rather use the native binary, delete the
`subtask(...)` block and the `solc` devDependency.

## Contract inventory

| Contract | Responsibility |
|---|---|
| `ArgusIdentity` | Soulbound ERC-721. Uniqueness, clearance, status, key rotation, x25519 pubkey. |
| `DesignationRegistry` | Non-transferable ERC-1155. Rank designations (one active) + functional roles (many). |
| `GroupRegistry` | Org units, project groups, need-to-know compartments. |
| `ResourceRegistry` | Namehash tree, classification, inheritance break, content hash, key bundle root. |
| `AccessRegistry` | ACEs, `effectivePermissions()`, MAC gates, delegation. Implements `IAuthorizer`. |
| `GrantWorkflow` | Propose / approve / execute, SoD rules, classification-tiered timelocks, break-glass. |
| `AuditAnchor` | Merkle roots of batched off-chain log lines, incident records. |

Libraries: `Permissions` (the 10-bit mask), `Principals` (one `bytes32` for
identity / designation / group / unit).

## Invariants, as executable tests

| Invariant | Test |
|---|---|
| INV-1 | clearance below classification never yields `P_READ` |
| INV-2 | revoking an identity zeroes access everywhere |
| INV-3 | a deny bit anywhere in the ancestor chain always wins |
| INV-4 | identity tokens never transfer |
| INV-5 | no SECRET+ ACE can be written outside the workflow |
| INV-6 | a child is never classified below its parent |
| INV-7 | proposer cannot be the approver |
| INV-8 | delegated permissions never exceed the delegator's |

Run `npx hardhat test` to see them pass. That is the slide.

## Measured gas

| Operation | Gas |
|---|---|
| `setAce` — first write to a new (node, principal) pair | ~173,000 |
| `setAce` — update to an existing ACE | ~57,500 |

The spec's 55–90k estimate holds for **updates**. A first write costs four cold
SSTOREs plus the enumerable push. Do not quote 55–90k for onboarding maths —
quote group grants instead: one ACE against a group principal covers every member,
which is the real answer to "500-person onboarding is expensive".

`effectivePermissions()` is a `view` — zero gas via `eth_call`.

## Two deliberate deviations from the spec

1. **`P_AUDIT` survives the need-to-know gate.** Figure 2 strips effective
   permissions to `P_LIST | P_READ_META` on compartment mismatch, which would stop
   an Internal Auditor from seeing the trail of any compartment they are not read
   into — contradicting §3.1. `P_AUDIT` grants history and effective-perms of
   others, never content, so keeping it leaks nothing. Marked in-line in
   `AccessRegistry._applyMandatoryAccessControl`.

2. **Contracts are not UUPS-upgradeable.** The spec calls for UUPS behind a Safe
   multisig. For a hackathon build the proxy layer adds deployment fragility and
   storage-gap bugs for no demo value. Every contract uses `AccessControl` with a
   swappable `authorizer` wire instead. If a judge asks, the honest answer is
   "upgradeability is a production-path item; we chose deployment reliability for
   the demo". Adding UUPS later is mechanical.

## Design notes worth defending

- **Why a registry, not a badge per (user, file).** An ERC-1155 badge cannot express
  read-but-not-download, cannot expire, cannot deny, and costs a mint per grant.
  Tokens stay where tokens are right (designations); ACEs handle authorization.
- **Why namehash.** `/BEL/Ghaziabad/RADAR-X/specs.pdf` folds to one `bytes32`
  client-side with zero RPC round-trips (`pathToNodeId` in `scripts/constants.ts`
  is the exact same fold the contract performs). Renaming is deliberately hard.
- **Deny overrides allow, globally.** Simpler than NTFS closest-ancestor-wins and
  strictly safer.
- **Two write paths.** `NODE_WRITER_ROLE` / `ACL_WRITER_ROLE` let the gateway's
  relayer submit on a user's behalf after the PDP runs and a step-up signature is
  verified; a user calling directly is checked against the live ACL. The relayer
  holds no privileged *authorization* role — a stolen relayer key burns gas.
- **`justificationHash` is mandatory.** Every grant carries a hash-committed
  written reason forever. `setAce` reverts on a zero hash.

## Inheritance break — a trap to remember in Chunk 4

`setInheritance(node, false)` does **not** snapshot inherited ACEs. The UI must
copy the current effective ACEs onto the node *before* calling it, or "lock this
folder down" silently removes everyone's access including the admin's own. This is
deliberate — the contract stays dumb, the snapshot is a gateway transaction batch.

## Demo scenario seeded by `scripts/seed.ts`

`/BEL/Ghaziabad/RADAR-X/specs.pdf` with three ACE sources at once:

```
sharma   -> 0x1bf   custodian, full control (direct)
verma    -> 0x007   LIST|READ_META|READ  — group grant + 14-day direct READ, no DOWNLOAD
kumar    -> 0x003   LIST|READ_META       — explicit DENY beat the inherited group READ
engg     -> 0x000   no grant, not in the RADAR-X compartment
auditor  -> 0x203   LIST|READ_META|AUDIT — sees everything about the file, never the file
```

Those five lines are the Security tab and the Effective Access calculator.

## What I could not verify from the build environment

- No Sepolia deployment or Etherscan verification — no RPC access. Scripts are
  written and run correctly against a local node.
- No Foundry invariant fuzzing or Slither/Mythril — not installable here. The eight
  invariants exist as Hardhat unit tests; porting them to Foundry `invariant_`
  functions is Chunk 5 work if time allows.
- No MetaMask / SIWE signing path — that is Chunk 2 and 4.

## Next

Chunk 2: NestJS gateway (SIWE auth, PDP, PEP), chain indexer, Postgres mirror.
