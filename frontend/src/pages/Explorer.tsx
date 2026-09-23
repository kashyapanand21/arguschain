import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, useSession } from "../lib/session";
import { TIERS, toMask, P } from "../lib/permissions";
import { Tier, BitStrip, Loading, Empty, ErrorBox, useAsync } from "../components/ui";

interface Row {
  tokenId: string;
  name: string;
  classification: number;
  ownerIdentity: string;
  version: number;
  effective: string;
  locked: boolean;
}

export default function Explorer() {
  const { session } = useSession();
  const { data, error, loading } = useAsync<Row[]>(() => api("/assets"), []);
  const [tier, setTier] = useState<number | "all">("all");

  const rows = useMemo(
    () => (data ?? []).filter((r) => tier === "all" || r.classification === tier),
    [data, tier]
  );

  const stats = useMemo(() => {
    const all = data ?? [];
    return {
      visible: all.length,
      readable: all.filter((r) => toMask(r.effective) & P.READ).length,
      locked: all.filter((r) => r.locked).length,
    };
  }, [data]);

  if (loading) return <Loading what="Reading the asset registry" />;
  if (error) return <ErrorBox error={error} />;

  return (
    <>
      <section className="panel stack">
        <span className="eyebrow">Asset registry</span>
        <h2>Files you can see</h2>
        <p className="lede">
          This list is resolved per person. Files more than one level above your
          clearance are not returned at all, so the count itself reveals nothing.
        </p>
        <div className="grid grid-3">
          <div className="stat" style={{ background: "var(--cyan)" }}>
            <div className="num">{stats.visible}</div>
            <div className="cap">Files visible to you</div>
          </div>
          <div className="stat" style={{ background: "var(--green)" }}>
            <div className="num">{stats.readable}</div>
            <div className="cap">You can open</div>
          </div>
          <div className="stat" style={{ background: "var(--yellow)" }}>
            <div className="num">{stats.locked}</div>
            <div className="cap">Locked, one level above your clearance</div>
          </div>
        </div>
      </section>

      <section className="stack">
        <div className="row">
          <button className={`btn btn-sm ${tier === "all" ? "btn-accent" : ""}`} onClick={() => setTier("all")}>
            All ({data?.length ?? 0})
          </button>
          {TIERS.map((t, i) => (
            <button key={t} className={`btn btn-sm ${tier === i ? "btn-accent" : ""}`} onClick={() => setTier(i)}>
              {t}
            </button>
          ))}
          {session?.roles.includes(1) && (
            <Link className="btn btn-sm btn-primary" to="/console/admin" style={{ marginLeft: "auto" }}>
              Register a new file
            </Link>
          )}
        </div>

        {rows.length === 0 ? (
          <Empty
            title="Nothing to show"
            body={tier === "all"
              ? "No files have been registered that you are cleared to see."
              : "No files at this classification are visible to you."}
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Token</th>
                  <th>File</th>
                  <th>Classification</th>
                  <th>Owner</th>
                  <th>Rev</th>
                  <th>Your permissions</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.tokenId} className={r.locked ? "locked-row" : ""}>
                    <td className="mono">#{r.tokenId}</td>
                    <td>
                      <b>{r.name}</b>
                      {r.locked && <div className="tiny muted" style={{ marginTop: 4 }}>
                        Locked — name and classification only
                      </div>}
                    </td>
                    <td><Tier level={r.classification} /></td>
                    <td className="mono">Identity #{r.ownerIdentity}</td>
                    <td className="mono">v{r.version}</td>
                    <td><BitStrip mask={r.effective} /></td>
                    <td>
                      {r.locked ? (
                        <button className="btn btn-sm" onClick={() => alert(
                          "Request sent to the file's custodian.\n\nIn the built system this opens a clearance-review request; the contract will not release content until clearance is raised through the approval workflow."
                        )}>Request access</button>
                      ) : (
                        <Link className="btn btn-sm btn-accent" to={`/console/asset/${r.tokenId}`}>Inspect</Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
