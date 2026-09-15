"use client";

/**
 * The queue view.
 *
 * Deliberately not the incident list. That page is risk-ranked, which answers
 * "what is worst?". A queue answers "what should I pick up next?", so it is
 * ordered oldest-first and leads with what nobody has claimed - the item most
 * likely to age past anyone noticing.
 */

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { SeverityBadge, StatusBadge, Tag } from "@/components/Badge";
import { api, ApiError, loadSession } from "@/lib/api";
import { age, relative } from "@/lib/format";
import type { HandoverReport, QueueIncident, Team } from "@/lib/types";

type Scope = "mine" | "unclaimed" | "open";

const SCOPES: Array<{ id: Scope; label: string; hint: string }> = [
  { id: "mine", label: "My work", hint: "Incidents assigned to you" },
  { id: "unclaimed", label: "Unclaimed", hint: "Nobody has picked these up" },
  { id: "open", label: "All open", hint: "Everything still being worked" },
];

export default function QueuesPage() {
  const [teams, setTeams] = useState<Team[]>([]);
  const [myTeamSlugs, setMyTeamSlugs] = useState<Set<string>>(new Set());
  const [team, setTeam] = useState<string>("");
  const [scope, setScope] = useState<Scope>("unclaimed");
  const [rows, setRows] = useState<QueueIncident[]>([]);
  const [handover, setHandover] = useState<HandoverReport | null>(null);
  const [showHandover, setShowHandover] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const email = loadSession()?.user?.email ?? "";

  const loadTeams = useCallback(async () => {
    const [all, mine] = await Promise.all([api.teams(), api.myTeams()]);
    setTeams(all.teams);
    setMyTeamSlugs(new Set(mine.teams.map((entry) => entry.slug)));
    return all.teams;
  }, []);

  const loadRows = useCallback(async () => {
    // A team filter uses the queue endpoint (which is oldest-first server
    // side); the unscoped views use the incident list with queue ordering.
    if (team) {
      const view = await api.queue(team, scope === "unclaimed");
      const incidents =
        scope === "mine"
          ? view.incidents.filter((row) => row.owner === email)
          : view.incidents;
      setRows(incidents);
      return;
    }
    const incidents = await api.incidents({
      open_only: true,
      order: "oldest",
      mine: scope === "mine" ? true : undefined,
      unclaimed: scope === "unclaimed" ? true : undefined,
      limit: 100,
    });
    setRows(
      incidents.map((incident) => ({
        key: incident.key,
        title: incident.title,
        status: incident.status,
        severity: incident.severity,
        risk_score: incident.risk_score,
        owner: incident.owner,
        principal: incident.principal,
        first_seen: incident.first_seen,
        acknowledged_at: incident.acknowledged_at,
        waiting_until: incident.waiting_until,
        version: incident.version,
      })),
    );
  }, [team, scope, email]);

  useEffect(() => {
    let cancelled = false;
    loadTeams()
      .then(() => !cancelled && setError(null))
      .catch((exc) => {
        if (!cancelled) setError(exc instanceof ApiError ? exc.message : "Could not load teams.");
      });
    return () => {
      cancelled = true;
    };
  }, [loadTeams]);

  useEffect(() => {
    let cancelled = false;
    loadRows()
      .then(() => !cancelled && setError(null))
      .catch((exc) => {
        if (!cancelled) setError(exc instanceof ApiError ? exc.message : "Could not load the queue.");
      });
    return () => {
      cancelled = true;
    };
  }, [loadRows]);

  useEffect(() => {
    if (!showHandover || !team) {
      setHandover(null);
      return;
    }
    let cancelled = false;
    api
      .handover(team)
      .then((report) => !cancelled && setHandover(report))
      .catch(() => !cancelled && setHandover(null));
    return () => {
      cancelled = true;
    };
  }, [showHandover, team]);

  async function refresh() {
    await Promise.all([loadTeams(), loadRows()]);
  }

  async function act(row: QueueIncident, action: "claim" | "unclaim") {
    setBusy(row.key);
    setError(null);
    setNotice(null);
    try {
      // The version we last read goes with the write: if somebody else moved
      // the incident meanwhile, the API answers 409 rather than clobbering it.
      if (action === "claim") {
        await api.claim(row.key, row.version);
        setNotice(`${row.key} is yours.`);
      } else {
        await api.unclaim(row.key, "returned to the queue", row.version);
        setNotice(`${row.key} is back in the queue.`);
      }
      await refresh();
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 409) {
        setError(`${exc.message} Reloading the queue.`);
        await refresh();
      } else {
        setError(exc instanceof ApiError ? exc.message : "That did not work.");
      }
    } finally {
      setBusy(null);
    }
  }

  const selected = teams.find((entry) => entry.slug === team);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Queues</h1>
          <p className="page-subtitle">
            Oldest first - a queue is worked from the bottom. {rows.length} shown.
          </p>
        </div>
        {team && (
          <button className="button" onClick={() => setShowHandover((value) => !value)}>
            {showHandover ? "Hide handover" : "Shift handover"}
          </button>
        )}
      </div>

      {teams.length === 0 ? (
        <div className="card">
          <p className="empty">
            No teams yet. An admin creates them with <span className="mono">POST /api/v1/teams</span>,
            then incidents can be routed to a queue.
          </p>
        </div>
      ) : (
        <div className="grid grid-4" style={{ marginBottom: 20 }}>
          {teams.map((entry) => {
            const active = entry.slug === team;
            return (
              <button
                key={entry.id}
                className="card"
                onClick={() => setTeam(active ? "" : entry.slug)}
                style={{
                  textAlign: "left",
                  cursor: "pointer",
                  borderColor: active ? "var(--series-1)" : undefined,
                }}
              >
                <div className="spread">
                  <span className="tile-label">{entry.name}</span>
                  {myTeamSlugs.has(entry.slug) && <Tag title="You are a member">mine</Tag>}
                </div>
                <div className="tile-value" style={{ fontSize: 28 }}>
                  {entry.open_incidents}
                </div>
                <div className="tile-foot">
                  {entry.unclaimed_incidents} unclaimed
                  {entry.is_default ? " · default queue" : ""}
                </div>
              </button>
            );
          })}
        </div>
      )}

      <div className="filters">
        {SCOPES.map((option) => (
          <button
            key={option.id}
            className={option.id === scope ? "button primary" : "button"}
            onClick={() => setScope(option.id)}
            title={option.hint}
          >
            {option.label}
          </button>
        ))}
        <span className="muted" style={{ fontSize: 13 }}>
          {selected ? `${selected.name} queue` : "every queue"}
        </span>
      </div>

      {error && <p className="error">{error}</p>}
      {notice && <p className="notice">{notice}</p>}

      {showHandover && handover && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-head">
            <h2 className="card-title">Shift handover · {handover.team.name}</h2>
            <span className="card-note">
              {handover.open_incidents} open · {handover.unclaimed} unclaimed
            </span>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Status</th>
                <th>Owner</th>
                <th>Last action</th>
              </tr>
            </thead>
            <tbody>
              {handover.incidents.map((row) => (
                <tr key={row.key}>
                  <td className="primary">
                    <Link href={`/incidents/${row.key}`}>{row.title}</Link>
                    <div className="muted mono" style={{ fontSize: 11 }}>
                      {row.key} · risk {row.risk_score}
                    </div>
                  </td>
                  <td>
                    <StatusBadge status={row.status} />
                  </td>
                  <td>{row.owner}</td>
                  <td className="secondary" style={{ fontSize: 12 }}>
                    <span className="mono">{row.last_action ?? "-"}</span>
                    {row.last_actor ? (
                      <div className="muted">
                        {row.last_actor}
                        {row.last_action_at ? ` · ${relative(row.last_action_at)}` : ""}
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="card">
        {rows.length === 0 ? (
          <p className="empty">
            Nothing here.{" "}
            {scope === "mine"
              ? "Claim something from the unclaimed queue."
              : "Generate telemetry from the "}
            {scope !== "mine" && <Link href="/lab">lab page</Link>}
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Status</th>
                <th>Severity</th>
                <th className="num">Risk</th>
                <th>Owner</th>
                <th>Waiting for</th>
                <th>Age</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const mine = row.owner === email;
                return (
                  <tr key={row.key}>
                    <td className="primary">
                      <Link href={`/incidents/${row.key}`}>{row.title}</Link>
                      <div className="muted mono" style={{ fontSize: 11 }}>
                        {row.key}
                        {row.principal ? ` · ${row.principal}` : ""}
                      </div>
                    </td>
                    <td>
                      <StatusBadge status={row.status} />
                    </td>
                    <td>
                      <SeverityBadge level={row.severity} />
                    </td>
                    <td className="num">{row.risk_score}</td>
                    <td>
                      {row.owner ? (
                        mine ? (
                          <Tag title="Assigned to you">you</Tag>
                        ) : (
                          <span style={{ fontSize: 12 }}>{row.owner}</span>
                        )
                      ) : (
                        <span className="muted">unclaimed</span>
                      )}
                    </td>
                    <td className="secondary" style={{ fontSize: 12 }}>
                      {row.waiting_until ? `until ${relative(row.waiting_until)}` : "-"}
                    </td>
                    <td title={row.first_seen}>{age(row.first_seen)}</td>
                    <td>
                      {mine ? (
                        <button
                          className="button"
                          disabled={busy === row.key}
                          onClick={() => act(row, "unclaim")}
                        >
                          Release
                        </button>
                      ) : row.owner ? (
                        <span className="muted" style={{ fontSize: 12 }}>
                          held
                        </span>
                      ) : (
                        <button
                          className="button primary"
                          disabled={busy === row.key}
                          onClick={() => act(row, "claim")}
                        >
                          Claim
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
