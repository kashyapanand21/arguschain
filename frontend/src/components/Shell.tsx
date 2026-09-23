import React, { useEffect, useState } from "react";
import { NavLink, Outlet, Link } from "react-router-dom";
import { useSession, api } from "../lib/session";
import { TIERS, ROLES, refusalFor } from "../lib/permissions";

const NAV = [
  { to: "/console", label: "Files", end: true },
  { to: "/console/proposals", label: "Proposals" },
  { to: "/console/risk", label: "Risk" },
  { to: "/console/admin", label: "Administration" },
];

function StatusBar() {
  const [chain, setChain] = useState<{ block: number; assets: number; identities: number } | null>(null);

  useEffect(() => {
    const load = () => api("/health/chain").then(setChain).catch(() => setChain(null));
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="topbar">
      <div className="wrap">
        <span><i className="dot" style={{ background: chain ? "var(--green)" : "var(--pink)" }} />
          {chain ? "Chain connected" : "Chain unreachable"}</span>
        {chain && <span>Block {chain.block}</span>}
        {chain && <span>{chain.assets} assets · {chain.identities} identities</span>}
        <span style={{ marginLeft: "auto" }}>Bharat Electronics Limited · PS 26125</span>
      </div>
    </div>
  );
}

/** Sessions last 15 minutes; warn before the user discovers it mid-action. */
function SessionClock({ onExpire }: { onExpire: () => void }) {
  const [left, setLeft] = useState(900);
  useEffect(() => {
    const t = setInterval(() => setLeft((s) => {
      if (s <= 1) { onExpire(); return 0; }
      return s - 1;
    }), 1000);
    return () => clearInterval(t);
  }, [onExpire]);

  const mins = Math.floor(left / 60);
  const secs = String(left % 60).padStart(2, "0");
  return (
    <span className={`chip mono ${left < 120 ? "chip-bad" : ""}`}>
      Session {mins}:{secs}
    </span>
  );
}

function SignInGate() {
  const { connect, signIn, connecting, address, error } = useSession();
  const r = error ? refusalFor(error.code) : null;

  return (
    <div className="page">
      <div className="wrap" style={{ maxWidth: 620 }}>
        <div className="panel stack">
          <span className="eyebrow">Restricted system</span>
          <h2>Sign in with your wallet</h2>
          <p className="lede">
            ArgusChain has no passwords. You prove who you are by signing a message
            with the key that controls your identity. The signature is checked
            against the identity registry before any permission is considered.
          </p>

          {address ? (
            <div className="spec-row"><span>Wallet</span><span>{address.slice(0, 10)}…{address.slice(-6)}</span></div>
          ) : (
            <button className="btn btn-block" onClick={connect}>Connect wallet</button>
          )}

          <button className="btn btn-primary btn-lg btn-block" onClick={signIn} disabled={connecting}>
            {connecting ? "Waiting for signature…" : "Sign in"}
          </button>

          {r && (
            <div className="panel panel-alert panel-flat">
              <h4>{r.title}</h4>
              <p style={{ marginTop: 6 }}>{error?.detail || r.body}</p>
            </div>
          )}

          <p className="tiny muted">
            Demo accounts: import the Hardhat test keys into MetaMask and switch
            accounts to act as the Admin, Manager, Auditor, User or Security Officer.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function Shell() {
  const { session, signOut, address } = useSession();

  return (
    <>
      <StatusBar />
      <header className="navbar">
        <div className="wrap">
          <Link to="/" className="brand">
            <b>ARGUSCHAIN</b>
            <small>Secure asset console</small>
          </Link>

          {session && (
            <nav className="navlinks">
              {NAV.map((n) => (
                <NavLink key={n.to} to={n.to} end={n.end}
                  className={({ isActive }) => `navlink ${isActive ? "active" : ""}`}>
                  {n.label}
                </NavLink>
              ))}
            </nav>
          )}

          {session ? (
            <div className="row">
              <SessionClock onExpire={signOut} />
              <div className="acting">
                <span className="tiny mono muted">Acting as</span>
                <span className="who">Identity #{session.identityId}</span>
                <div className="row" style={{ gap: 5 }}>
                  {session.roles.map((r) => <span key={r} className="chip chip-role">{ROLES[r]}</span>)}
                  <span className={`chip chip-t${session.clearance + 1}`}>{TIERS[session.clearance]}</span>
                </div>
              </div>
              <button className="btn btn-sm" onClick={signOut}>Sign out</button>
            </div>
          ) : (
            <span className="chip mono">{address ? "Wallet connected" : "Not signed in"}</span>
          )}
        </div>
      </header>

      {session ? (
        <main className="page">
          <div className="wrap stack-lg"><Outlet /></div>
        </main>
      ) : (
        <SignInGate />
      )}
    </>
  );
}
