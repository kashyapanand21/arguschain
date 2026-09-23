import React, { useState } from "react";
import { Link } from "react-router-dom";
import { BITS, TIERS, approvalPolicy } from "../lib/permissions";

const FAQS = [
  {
    q: "How is this different from a database with a permissions table?",
    a: "Three ways. Every permission traces to a blockchain event with a transaction hash, so it can be verified without trusting us. The rules run inside smart contracts, so a database administrator cannot grant themselves access with a single query. And the audit trail is hash-chained, so the people being audited cannot quietly rewrite it.",
  },
  {
    q: "Can an administrator read the files?",
    a: "No. An administrator can grant access to a file but holds no content permission on it. That is enforced in the contract's permission resolver, not by policy or by convention, and it holds regardless of the administrator's own clearance. The same rule applies in reverse to auditors: they see the metadata, the access list and the full history of every file, and never its contents.",
  },
  {
    q: "Where are the files stored?",
    a: "Not on the blockchain. Only the file's SHA-256 hash goes on chain. The file itself is encrypted with its own key and stored on the organisation's infrastructure, with that key wrapped by a master key held separately. On every read the file is decrypted, re-hashed, and compared against the hash on chain before a single byte reaches the reader.",
  },
  {
    q: "What happens if someone's key is stolen?",
    a: "The key is rotated on the identity registry, and every permission survives untouched. Access is tied to the identity rather than to a wallet address, and every authorisation check reads the current controlling key live, so the old key stops working the moment the rotation is recorded.",
  },
  {
    q: "Can you revoke a file someone already downloaded?",
    a: "No, and neither can any other system. What we do instead is make it accountable: everything after the revocation is blocked immediately, and every release before it is permanently logged against a named identity with a timestamp, so an investigation can prove exactly who took what and when.",
  },
];

function Faq() {
  const [open, setOpen] = useState<number | null>(0);
  return (
    <div>
      {FAQS.map((f, i) => (
        <div className="faq-item" key={i}>
          <button className="faq-q" aria-expanded={open === i} onClick={() => setOpen(open === i ? null : i)}>
            <span>{f.q}</span>
            <span className="faq-toggle" aria-hidden>{open === i ? "−" : "+"}</span>
          </button>
          {open === i && <div className="faq-a"><p>{f.a}</p></div>}
        </div>
      ))}
    </div>
  );
}

const ANCHORS = [
  { t: "One person, one identity", b: "Each person holds a non-transferable credential bound to a decentralised identifier. It cannot be sold, lent or moved between people, and the contract refuses a second identity for the same employee." },
  { t: "Roles as tokens", b: "Admin, Manager, Auditor, User and Security Officer are tokens. Granting a role mints one, revoking burns it, and peer-to-peer transfer is disabled, so a role can never leave through a wallet." },
  { t: "Files as traceable assets", b: "Every file becomes a token carrying an immutable SHA-256 hash. Only an administrator can create one, the same content can never be registered twice, and ordinary transfers always revert." },
  { t: "Permissions with teeth", b: "Eight independent permissions per person per file, plus explicit deny, an expiry date, and a written reason that is hash-committed on chain and kept forever." },
  { t: "Nobody holds both keys", b: "The account that grants access cannot read the content. The account that audits everything cannot read the content either. Neither restriction depends on anyone behaving well." },
  { t: "Four eyes on classified grants", b: "Above a classification threshold, a grant is a proposal. Someone other than the proposer must approve it, and the highest tiers need a Security Officer and a waiting period." },
];

const STAGES = [
  { n: "Signature", k: "Deterministic", b: "The wallet signs a login message. The signer must be the key that currently controls the identity." },
  { n: "Identity", k: "Deterministic", b: "Is the credential active, in tenure, and neither suspended nor revoked?" },
  { n: "Permissions", k: "Deterministic", b: "Collect every grant that applies, add the allowed bits, then subtract every denied bit." },
  { n: "Clearance gate", k: "Deterministic", b: "If clearance is below the file's classification, content permissions are stripped even though they were granted." },
  { n: "Risk score", k: "Advisory", b: "Rules flag unusual behaviour and explain why. This layer can never grant or revoke anything." },
];

export default function Landing() {
  return (
    <>
      <div className="topbar">
        <div className="wrap">
          <span><i className="dot" />Smart India Hackathon 2026</span>
          <span>Problem statement 26125</span>
          <span>Bharat Electronics Limited</span>
          <span style={{ marginLeft: "auto" }}>Team Blackfyre</span>
        </div>
      </div>

      <header className="navbar">
        <div className="wrap">
          <Link to="/" className="brand"><b>ARGUSCHAIN</b><small>Secure asset console</small></Link>
          <nav className="navlinks">
            <a className="navlink" href="#problem">The problem</a>
            <a className="navlink" href="#built">What we built</a>
            <a className="navlink" href="#lifecycle">How it works</a>
            <a className="navlink" href="#model">Permissions</a>
            <a className="navlink" href="#scope">Scope</a>
            <a className="navlink" href="#faq">Questions</a>
          </nav>
          <Link className="btn btn-primary" to="/console">Open the console</Link>
        </div>
      </header>

      <main className="page">
        <div className="wrap stack-lg">

          <section className="hero">
            <div className="panel stack">
              <span className="eyebrow">Blockchain and cybersecurity</span>
              <h1>Identity, access control and digital asset management, enforced by contract.</h1>
              <p className="lede">
                ArgusChain gives every person a decentralised identity, turns every classified
                document into a uniquely traceable asset carrying an immutable hash, and decides
                who may open it using rules that run on chain — not rules a server administrator
                could quietly rewrite.
              </p>
              <div className="row">
                <Link className="btn btn-primary btn-lg" to="/console">Open the console</Link>
                <a className="btn" href="#built">See what we built</a>
              </div>
            </div>

            <div className="panel panel-info stack">
              <h3>What runs today</h3>
              <div className="stack" style={{ marginTop: 0 }}>
                {[
                  ["Identity", "Decentralised identifier + soulbound credential"],
                  ["Roles", "Five role tokens, non-transferable"],
                  ["Assets", "Token per file, SHA-256 anchored"],
                  ["Permissions", "8 bits, deny, expiry, justification"],
                  ["Encryption", "AES-256-GCM, per-file key"],
                  ["Approvals", "1 or 2 signers by classification"],
                ].map(([k, v]) => (
                  <div className="spec-row" key={k}><span>{k}</span><span>{v}</span></div>
                ))}
              </div>
              <p className="tiny">
                The landing page is public. Opening the console asks for a wallet
                signature; an existing session goes straight through.
              </p>
            </div>
          </section>

          <section id="problem" className="panel panel-alert stack">
            <span className="eyebrow">Why this needs a chain</span>
            <h2>A permissions table in a database cannot answer the questions a defence audit asks.</h2>
            <ol className="numbered" style={{ listStyle: "none", padding: 0, margin: 0 }}>
              <li><span className="n">1</span><p><b>The operator can edit it.</b> A database administrator, or anyone who reaches the server, can grant themselves read access with one statement and leave no trace that survives scrutiny.</p></li>
              <li><span className="n">2</span><p><b>The log can be edited by the people it audits.</b> Conventional audit tables and syslog streams can be truncated or selectively rewritten by exactly the privileged insiders an audit is meant to catch.</p></li>
              <li><span className="n">3</span><p><b>There is no proof of who approved what.</b> When a classified specification is accessed, a database row cannot demonstrate, to anyone who did not already trust it, which named person authorised that access and on what stated grounds.</p></li>
            </ol>
          </section>

          <section id="built" className="stack">
            <div className="stack">
              <span className="eyebrow">Implemented</span>
              <h2>Six things the contracts guarantee</h2>
              <p className="lede">Each of these is enforced in Solidity and covered by the test suite.</p>
            </div>
            <div className="grid grid-3">
              {ANCHORS.map((a) => (
                <article className="panel" key={a.t}>
                  <h3>{a.t}</h3>
                  <p style={{ marginTop: 12 }}>{a.b}</p>
                </article>
              ))}
            </div>
          </section>

          <section id="lifecycle" className="panel stack">
            <div className="spread">
              <div>
                <span className="eyebrow">Request lifecycle</span>
                <h2 style={{ marginTop: 14 }}>What happens when someone opens a file</h2>
              </div>
              <div className="row">
                <span className="chip chip-ok">Deterministic</span>
                <span className="chip chip-warn">Advisory</span>
              </div>
            </div>
            <div className="pipeline">
              {STAGES.map((s, i) => (
                <div className={`stage ${s.k === "Advisory" ? "stage-advisory" : ""}`} key={s.n}>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <span className="tiny mono muted">Stage {i + 1}</span>
                    <span className="tiny mono"><b>{s.k}</b></span>
                  </div>
                  <h4 style={{ margin: "8px 0" }}>{s.n}</h4>
                  <p className="tiny">{s.b}</p>
                </div>
              ))}
            </div>
            <p className="lede">
              Only after all five does the file get decrypted, re-hashed against the chain, and
              served — and the decision, allowed or refused, is written to an append-only log.
            </p>
          </section>

          <section id="model" className="grid grid-2">
            <div className="panel stack">
              <span className="eyebrow">Eight permissions</span>
              <h3>Access is not a yes or a no</h3>
              <p>
                Every person holds eight independent permissions on every file. Reading and
                exporting are deliberately separate, so "view it, but you cannot take a copy"
                is a first-class state rather than a workaround.
              </p>
              <div className="stack" style={{ marginTop: 0 }}>
                {BITS.map((b, i) => (
                  <div className="spec-row" key={b.key}>
                    <span>Bit {i} · {b.name}</span>
                    <span style={{ fontWeight: 400 }}>{b.desc}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel stack">
              <span className="eyebrow">Five levels</span>
              <h3>Clearance meets classification</h3>
              <p>
                People hold a clearance, files hold a classification, on the same five-level
                scale. A grant can be overridden: if your clearance sits below the file's
                classification, content permissions are stripped even though someone granted them.
              </p>
              <div className="stack" style={{ marginTop: 0 }}>
                {TIERS.map((t, i) => {
                  const p = approvalPolicy(i);
                  return (
                    <div className="spec-row" key={t}>
                      <span className={`chip chip-t${i + 1}`}>{t}</span>
                      <span style={{ fontWeight: 400 }}>
                        {p.approvals === 0 ? "Immediate" : `${p.approvals} approver${p.approvals > 1 ? "s" : ""}`}
                        {p.officer ? " · Security Officer" : ""}
                        {p.timelock !== "none" ? ` · ${p.timelock} wait` : ""}
                      </span>
                    </div>
                  );
                })}
              </div>
              <p className="tiny muted">
                A file more than one level above your clearance is not listed at all, and the
                interface never confirms that it exists.
              </p>
            </div>
          </section>

          <section id="scope" className="panel stack">
            <span className="eyebrow">Honest scope</span>
            <h2>What is built, and what is not</h2>
            <p className="lede">
              We claim only what runs. Everything on the left exists in the repository and is
              exercised by the test suite; everything on the right is design work we have not built.
            </p>
            <div className="grid grid-2">
              <div className="panel panel-flat">
                <h3>Built and running</h3>
                <ul style={{ paddingLeft: 20, marginTop: 14 }}>
                  <li>Seven Solidity contracts, full test suite passing</li>
                  <li>Identity registration proved by an on-chain signature check</li>
                  <li>Permission resolver with deny, expiry and the clearance gate</li>
                  <li>Propose, approve and execute for classified grants</li>
                  <li>AES-256-GCM per-file encryption with a wrapped key</li>
                  <li>Hash verification against the chain on every read</li>
                  <li>Hash-chained decision log for reads and refusals</li>
                  <li>Rule-based risk scoring with plain-language reasons</li>
                </ul>
              </div>
              <div className="panel panel-flat">
                <h3>Roadmap, not claimed</h3>
                <ul style={{ paddingLeft: 20, marginTop: 14 }}>
                  <li>Deployment to a permissioned production network</li>
                  <li>Hardware-backed key custody in place of the demo key store</li>
                  <li>End-to-end encryption, with decryption in the browser</li>
                  <li>Merkle anchoring of the decision log to the chain</li>
                  <li>A trained anomaly model, once real access data exists</li>
                  <li>Folder trees with inherited permissions</li>
                </ul>
              </div>
            </div>
          </section>

          <section id="faq" className="stack">
            <div className="stack">
              <span className="eyebrow">Questions</span>
              <h2>Frequently asked</h2>
            </div>
            <Faq />
          </section>

          <section className="panel panel-tint stack">
            <h2>Try it yourself</h2>
            <p className="lede">
              The console runs against a local chain with five seeded people. Sign in as each
              one and watch the same file answer differently.
            </p>
            <div className="row">
              <Link className="btn btn-lg" to="/console">Open the console</Link>
            </div>
          </section>

        </div>
      </main>

      <footer className="footer">
        <div className="wrap grid grid-3">
          <div>
            <h3>ArgusChain</h3>
            <p style={{ marginTop: 12, opacity: .8 }}>
              Identity, access control and digital asset management for classified
              engineering documents.
            </p>
          </div>
          <div className="mono tiny stack" style={{ lineHeight: 2 }}>
            <div>Smart India Hackathon 2026</div>
            <div>Problem statement 26125</div>
            <div>Bharat Electronics Limited</div>
            <div>Team Blackfyre</div>
          </div>
          <div className="mono tiny stack" style={{ lineHeight: 2 }}>
            <div>ArgusIdentity.sol</div>
            <div>RoleRegistry.sol</div>
            <div>AssetNFT.sol</div>
            <div>AccessRegistry.sol</div>
            <div>GrantWorkflow.sol</div>
            <div>AuditAnchor.sol</div>
          </div>
        </div>
      </footer>
    </>
  );
}
