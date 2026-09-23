
# ArgusChain

Blockchain-based platform for identity, access control and digital asset management.

Smart India Hackathon 2026 · Problem statement **26125** · Bharat Electronics Limited · Team Blackfyre

---

## What this is

A system for managing classified engineering documents where the access rules are
enforced by smart contracts rather than by trusting a server administrator.

Three claims it makes good on:

- **An administrator can grant access to a file but can never read it.** Not by policy — the
  permission resolver gives Admin role holders exactly two permissions on every asset, and
  neither of them is a content permission.
- **An auditor sees everything about a file except the file.** Same mechanism, enforced in
  the opposite direction.
- **Above a classification threshold, nobody grants access alone.** The request becomes a
  proposal, and the contract refuses to let the proposer approve it.

Every identity, role, asset, permission change and transfer is an on-chain event. Reads and
refusals go to a hash-chained log, because writing every read to the chain would not survive
contact with real volume.

---

## Architecture

```
Browser (React + Vite)          signs every state change in MetaMask
      │
      │  /api  →  Vite dev proxy
      ▼
Backend (Node + Express)        never signs a transaction; holds no private key
      ├─ SIWE auth              signature → live DID owner → identity status → session
      ├─ PDP                    asks the chain on every request, never a cache
      ├─ File service           AES-256-GCM, per-file key, hash re-verified on read
      ├─ Risk rules             advisory score with stated reasons
      └─ SQLite                 two tables: stored files, decision log
      │
      ▼
Chain (Hardhat local)           the authority for identity, roles, assets, permissions
```

### Contracts

| Contract                | Standard                     | Responsibility                                             |
| ----------------------- | ---------------------------- | ---------------------------------------------------------- |
| `EthereumDIDRegistry` | ERC-1056                     | Decentralised identifier and its current controlling key   |
| `ArgusIdentity`       | ERC-721 + ERC-5192           | Soulbound credential carrying clearance, status and tenure |
| `RoleRegistry`        | ERC-1155, non-transferable   | Admin, Manager, Auditor, User, Security Officer            |
| `AssetNFT`            | ERC-721, controlled transfer | One token per file, immutable SHA-256, admin-only mint     |
| `AccessRegistry`      | purpose-built                | Per-asset permissions, deny, expiry, the resolver          |
| `GrantWorkflow`       | purpose-built                | Propose, approve, execute — with separation of duty       |
| `AuditAnchor`         | purpose-built                | Merkle roots of batched decision-log lines                 |

### Why a registry and not a token for permissions

Identity, roles and assets are tokens because possession is the right question for them.
Per-asset permissions are not: a token balance cannot express read-but-not-download, cannot
expire, and cannot deny. So they live in a purpose-built table instead.

---

## The permission model

Eight independent bits per person per asset. Reading and exporting are separate on purpose,
so "view it, but you cannot take a copy" is a first-class state.

| Bit | Name            | Meaning                                   |
| --- | --------------- | ----------------------------------------- |
| 0   | `P_LIST`      | Appears in a listing                      |
| 1   | `P_READ_META` | Size, hash, version, owner, access list   |
| 2   | `P_READ`      | View the decrypted content                |
| 3   | `P_DOWNLOAD`  | Export the raw file                       |
| 4   | `P_WRITE`     | Upload a new version                      |
| 5   | `P_SHARE`     | Delegate a subset of your own access      |
| 6   | `P_ADMIN`     | Edit the access list                      |
| 7   | `P_AUDIT`     | Full history and others' effective access |

People hold a **clearance** and files hold a **classification**, on the same five-level scale:
PUBLIC, RESTRICTED, CONFIDENTIAL, SECRET, TOP_SECRET.

A grant can be overridden. If clearance sits below classification, content bits are stripped
even though they were genuinely granted, and a file more than one level above clearance is
never listed at all.

### Approval routing

| Classification      | Approvers besides the proposer | Security Officer | Waiting period |
| ------------------- | ------------------------------ | ---------------- | -------------- |
| PUBLIC / RESTRICTED | none                           | –               | –             |
| CONFIDENTIAL        | 1                              | –               | –             |
| SECRET              | 2                              | required         | 1 hour         |
| TOP_SECRET          | 2, all TOP_SECRET cleared      | required         | 24 hours       |

---

## Running it

Three processes, three terminals. Node 22 LTS is recommended; Node 24 prints a harmless
`UV_HANDLE_CLOSING` assertion when a script exits on Windows.

### 1. Chain

```bash
npm install
npx hardhat test          # 28 passing
npx hardhat node          # leave running
```

In a second terminal:

```bash
npm run deploy:local
npm run seed:local
```

The seed creates five identities with their role tokens, three assets, a clearance uplift
through the four-eyes workflow, and both a direct and a workflow-routed grant.

### 2. Backend

```bash
cd backend
npm install
npx prisma migrate deploy
npm run dev               # http://localhost:3000
```

Create `backend/.env`:

```
JWT_SECRET=<a long random string>
SIWE_DOMAIN=localhost:5173
RPC_URL=http://127.0.0.1:8545
KEK_SECRET=<a long random string>
```

`SIWE_DOMAIN` must match the address you open in the browser exactly. Opening the app at
`127.0.0.1:5173` while this says `localhost:5173` fails signature verification.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev               # http://localhost:5173
```

### Wallet

Add a network in MetaMask: RPC `http://127.0.0.1:8545`, chain id `31337`. Import the Hardhat
test keys to act as each person. Switching accounts signs you out, deliberately.

| Account | Person    | Role             | Clearance    |
| ------- | --------- | ---------------- | ------------ |
| #0      | R. Sharma | Admin            | RESTRICTED   |
| #2      | A. Verma  | Manager          | CONFIDENTIAL |
| #3      | K. Rao    | Auditor          | RESTRICTED   |
| #4      | S. Kumar  | User             | RESTRICTED   |
| #5      | P. Nair   | Security Officer | TOP_SECRET   |

### Resetting

The chain, the database and the stored ciphertext all carry token ids, so they must be reset
together:

```bash
cd backend
npm run reset             # stop the backend first
```

---

## Demo script

| #  | Action                                                           | What it proves                                                    |
| -- | ---------------------------------------------------------------- | ----------------------------------------------------------------- |
| 1  | Sign in as the Manager                                           | Identity resolved from a signature, not a password                |
| 2  | Sign in from an unregistered wallet                              | A valid signature is refused before any permission check          |
| 3  | Open the same file as Manager, User and Auditor                  | One file, three different answers                                 |
| 4  | Open the Effective access tab as the User on a CONFIDENTIAL file | A granted permission stripped by the clearance gate, step by step |
| 5  | Open the same tab as the Auditor                                 | Metadata and audit granted, content refused, by role rule         |
| 6  | Register a file as the Admin                                     | Wallet-signed mint; the server never signs                        |
| 7  | Register the same file again                                     | Duplicate content rejected by the contract                        |
| 8  | Try a CONFIDENTIAL registration                                  | Direct creation refused; it must go through approvals             |
| 9  | Read three files quickly                                         | Risk score rises with stated reasons, step-up demanded            |
| 10 | Corrupt a stored file, then read it                              | Integrity check refuses it before a byte is served                |
| 11 | Open the History tab                                             | Chain events beside the hash-chained decision log                 |

---

## What is built, and what is not

### Built and tested

- Seven Solidity contracts, 28 tests covering every invariant in the specification that
  applies to this design
- Identity registration proved by an on-chain EIP-712 signature check against the DID registry
- Three uniqueness guarantees: one identity per employee, one per DID, no transfers
- Permission resolver with deny override, time windows, the clearance gate and role rules
- Propose, approve and execute, including the proposer-is-not-approver rule and timelocks
- AES-256-GCM per-file encryption with a wrapped key
- Hash verified against the chain on every read, in two independent ways
- Hash-chained decision log for reads and refusals
- Rule-based risk scoring with plain-language reasons
- Landing page and console: files, asset detail, effective access, access list, history,
  risk feed, administration

### Not built — roadmap, not claimed

- Deployment to a permissioned production network; this runs on a local chain
- Hardware-backed key custody in place of the demo key store
- End-to-end encryption with decryption in the browser. In this build the server is inside
  the trust boundary for plaintext, in memory only
- Merkle anchoring of the decision log; the contract exists, the batching job does not
- A trained anomaly model. The rule engine is the Tier 1 layer; the model needs real access
  data, which does not exist yet
- Folder trees with inherited permissions
- The proposals screen in the console. The workflow runs in the contracts and is covered by
  tests, but the UI does not yet drive it

### Known limits

- **Revocation cannot recall released plaintext.** No system can. Everything after a
  revocation is blocked, and every release before it is logged against a named identity.
- **Role tokens are held by address.** After a key rotation, per-asset grants survive because
  they key on identity, but role tokens stay with the old address until re-granted.
- **The risk engine is time-sensitive.** The off-hours rule fires between 22:00 and 06:00, so
  a late-night demo will demand step-up on every read.

---

## Repository layout

```
contracts/          Solidity sources
scripts/            deploy and seed
test/               Hardhat test suite
deployments/        addresses written by deploy, read by the backend
backend/
  src/chain.ts      contract instances, read-only
  src/pdp.ts        the authorization decision and its reason codes
  src/risk.ts       the rule engine
  src/storage.ts    encryption and the key wrap
  src/audit.ts      hash-chained decision log
  src/controllers/  auth, assets, audit
  src/dev/          scripts for driving the API without a browser
frontend/
  src/pages/        landing, explorer, asset detail, admin, risk
  src/lib/          API client, session, permission helpers
```

---

## Design decisions worth defending

**Authentication is not authorization.** A signature proves who is asking. Roles and
permissions decide what they may do. The two checks are separate and ordered, and the second
never runs if the first fails.

**The chain is asked live, on every request.** Not the session token, not a cache. A
suspension takes effect immediately even while a valid session is open.

**Every refusal has its own reason.** There are a dozen distinct refusal codes, each with its
own message. A generic "access denied" would discard the system's main advantage.

**The risk layer only advises.** It cannot grant, revoke or suspend. Fixed thresholds turn a
score into an action, and suspension is always a human decision. If the scoring is wrong,
nothing catastrophic follows.

**The backend holds no private key.** Every state change is signed in the user's own wallet.
The contracts enforce the rules; the backend cannot bypass them.
