import React from "react";
import { api } from "../lib/session";
import { Loading, ErrorBox, Empty, useAsync } from "../components/ui";
import { approvalPolicy, TIERS } from "../lib/permissions";

/* -------------------------------------------------------------------- risk */

export function Risk() {
  const { data, error, loading } = useAsync<any[]>(() => api("/decisions"), []);
  if (loading) return <Loading what="Reading the decision log" />;
  if (error) return <ErrorBox error={error} />;

  const flagged = (data ?? []).filter((d) => d.riskScore > 0 || d.reasonCode !== "ALLOW");

  return (
    <>
      <section className="panel stack">
        <span className="eyebrow">Behavioural monitoring</span>
        <h2>Unusual access, and why it was flagged</h2>
        <p className="lede">
          Rules score every request against the access log: activity outside working
          hours, many different files in a short window, repeated refusals, and the
          first time someone opens a file.
        </p>
        <div className="grid grid-3">
          <div className="stat" style={{ background: "var(--green)" }}>
            <div className="num">0–40</div><div className="cap">Allowed and logged</div>
          </div>
          <div className="stat" style={{ background: "var(--yellow)" }}>
            <div className="num">41–80</div><div className="cap">Allowed after re-confirmation</div>
          </div>
          <div className="stat" style={{ background: "var(--pink)" }}>
            <div className="num">81+</div><div className="cap">Refused and reported</div>
          </div>
        </div>
        <div className="panel panel-flat panel-tint">
          <h4>This layer only advises</h4>
          <p className="tiny" style={{ marginTop: 6 }}>
            It cannot grant access, revoke access, or suspend anyone. Fixed thresholds
            in the policy engine turn a score into an action, and suspension is always
            a human decision.
          </p>
        </div>
      </section>

      <section className="stack">
        <h3>Recent activity ({flagged.length})</h3>
        {!flagged.length ? (
          <Empty title="Nothing flagged" body="No scored or refused requests have been recorded yet." />
        ) : (
          <div className="timeline">
            {flagged.map((d) => (
              <div className={`tl-item ${d.reasonCode === "ALLOW" ? "" : "deny"}`} key={d.id}>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <div className="row">
                    <span className={`chip mono ${d.riskScore > 80 ? "chip-bad" : d.riskScore > 40 ? "chip-warn" : "chip-ok"}`}>
                      Risk {d.riskScore}
                    </span>
                    <span className="chip mono">{d.reasonCode}</span>
                    <span className="tiny">Identity #{d.identityId}{d.tokenId ? ` · token #${d.tokenId}` : ""}</span>
                  </div>
                  <span className="tiny mono muted">{new Date(d.ts).toLocaleString()}</span>
                </div>
                {d.reasons?.length > 0 && (
                  <ul className="tiny" style={{ margin: "8px 0 0", paddingLeft: 18 }}>
                    {d.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}
                  </ul>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

/* --------------------------------------------------------------- proposals */

export function Proposals() {
  return (
    <>
      <section className="panel stack">
        <span className="eyebrow">Four-eyes approvals</span>
        <h2>Grants that need a second person</h2>
        <p className="lede">
          Above a classification threshold no one can grant access alone. The request
          becomes a proposal, someone else approves it, and only then can it execute.
        </p>
      </section>

      <section className="stack">
        <h3>What each classification requires</h3>
        <div className="table-scroll">
          <table>
            <thead>
              <tr><th>Classification</th><th>Approvers besides the proposer</th><th>Security Officer</th><th>Waiting period</th></tr>
            </thead>
            <tbody>
              {TIERS.map((t, i) => {
                const p = approvalPolicy(i);
                return (
                  <tr key={t}>
                    <td><span className={`chip chip-t${i + 1}`}>{t}</span></td>
                    <td className="mono">{p.approvals === 0 ? "None — immediate" : p.approvals}</td>
                    <td className="mono">{p.officer ? "Required" : "Not required"}</td>
                    <td className="mono">{p.timelock}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel panel-tint stack">
        <h3>Not wired into this console yet</h3>
        <p>
          The propose, approve and execute workflow runs in the contracts and is
          covered by the test suite, including the rule that a proposer can never
          approve their own request. This screen does not yet drive it; the flow is
          demonstrated from the command line.
        </p>
        <p className="tiny mono">
          Needed to finish it: read endpoints for open proposals, and wallet-signed
          calls to propose, approve and execute.
        </p>
      </section>
    </>
  );
}
