"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { AttackPath } from "@/components/AttackPath";
import { SeverityBadge, StatusBadge, Tag } from "@/components/Badge";
import { RiskMeter } from "@/components/RiskMeter";
import { CommentThread } from "@/components/CommentThread";
import { Timeline } from "@/components/Timeline";
import { api, ApiError, loadSession } from "@/lib/api";
import { dateTime, duration, statusLabel } from "@/lib/format";
import type {
  IncidentComment,
  IncidentDetail,
  IncidentWatcher,
  Session,
  Team,
} from "@/lib/types";

export default function IncidentPage() {
  const params = useParams<{ reference: string }>();
  const reference = params.reference;

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [note, setNote] = useState("");
  const [playbook, setPlaybook] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [teams, setTeams] = useState<Team[]>([]);
  const [session, setSession] = useState<Session | null>(null);
  const [waitReason, setWaitReason] = useState("");
  const [waitHours, setWaitHours] = useState(4);
  const [transferTeam, setTransferTeam] = useState("");
  const [transferReason, setTransferReason] = useState("");
  const [threads, setThreads] = useState<IncidentComment[]>([]);
  const [watchers, setWatchers] = useState<IncidentWatcher[]>([]);

  const load = useCallback(async () => {
    try {
      const [detail, transitions, comments, watching] = await Promise.all([
        api.incident(reference),
        api.allowedTransitions(reference),
        api.comments(reference),
        api.watchers(reference),
      ]);
      setIncident(detail);
      setAllowed(transitions.allowed);
      setThreads(comments.threads);
      setWatchers(watching.watchers);
      setError(null);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Could not load the incident.");
    }
  }, [reference]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    setSession(loadSession());
    // Teams drive the transfer picker. A viewer with no queues configured
    // simply does not see it, rather than seeing an empty control.
    api
      .teams()
      .then((response) => setTeams(response.teams))
      .catch(() => setTeams([]));
  }, []);

  async function act(fn: () => Promise<unknown>, successMessage: string) {
    setBusy(true);
    setMessage(null);
    setError(null);
    try {
      await fn();
      setMessage(successMessage);
      await load();
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 409) {
        // Somebody else moved the incident while this page was open. Reload
        // first so the analyst is looking at what is actually there - and only
        // then set the message, because load() clears `error` on success and
        // would otherwise swallow the explanation.
        await load();
        setError(`${exc.message} \u2014 the page has been reloaded.`);
      } else {
        setError(exc instanceof ApiError ? exc.message : "Action failed.");
      }
    } finally {
      setBusy(false);
    }
  }

  /**
   * Post a comment or a reply, and surface handles that matched nobody: a
   * dropped mention leaves the author believing somebody was notified.
   */
  async function postComment(body: string, parentId?: string) {
    setBusy(true);
    setMessage(null);
    setError(null);
    try {
      const result = await api.addComment(reference, body, parentId);
      setThreads(result.threads);
      setWatchers(result.watchers);
      if (!parentId) setNote("");
      const notified = result.mentioned.length
        ? ` Notified ${result.mentioned.join(", ")}.`
        : "";
      setMessage(`Comment added.${notified}`);
      if (result.unresolved_mentions.length > 0) {
        setError(
          `No match for @${result.unresolved_mentions.join(", @")} - nobody was notified.`,
        );
      }
      await load();
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Could not add the comment.");
    } finally {
      setBusy(false);
    }
  }

  async function toggleWatch() {
    setBusy(true);
    try {
      const result = watching ? await api.unwatch(reference) : await api.watch(reference);
      setWatchers(result.watchers);
      setMessage(result.watching ? "Watching this incident." : "No longer watching.");
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Could not change the watch.");
    } finally {
      setBusy(false);
    }
  }

  /** Hours -> an ISO wake-up time for the waiting state. */
  function wakeUpAt(hours: number): string {
    return new Date(Date.now() + hours * 3600 * 1000).toISOString();
  }

  if (error && !incident) {
    return (
      <>
        <div className="page-head">
          <h1 className="page-title">Incident</h1>
        </div>
        <p className="error">{error}</p>
      </>
    );
  }

  if (!incident) {
    return <p className="empty">Loading incident…</p>;
  }

  const watching = watchers.some((watcher) => watcher.email === session?.user?.email);

  const selectedPlaybook =
    incident.suggested_playbooks.find((item) => item.name === playbook) ?? null;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">
            {incident.key} · {incident.title}
          </h1>
          <p className="page-subtitle">
            {incident.principal ?? "unattributed"} ·{" "}
            {incident.source_ips.join(", ") || "no source address"} ·{" "}
            {incident.hostnames.join(", ") || "no host"} · spans{" "}
            {duration(incident.first_seen, incident.last_seen)}
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <StatusBadge status={incident.status} />
          <SeverityBadge level={incident.severity} score={incident.risk_score} />
        </div>
      </div>

      {error && <p className="error">{error}</p>}
      {message && <p className="notice">{message}</p>}

      <div className="grid grid-2">
        <div className="card">
          <div className="card-head">
            <h2 className="card-title">Risk</h2>
            <span className="card-note">experimental scoring model</span>
          </div>
          <RiskMeter score={incident.risk_score} />
          <ul className="stack" style={{ marginTop: 12, paddingLeft: 18, fontSize: 13 }}>
            {incident.risk_factors.map((factor) => (
              <li key={factor} className="secondary">
                {factor}
              </li>
            ))}
          </ul>
        </div>

        <div className="card">
          <div className="card-head">
            <h2 className="card-title">MITRE ATT&amp;CK</h2>
            <span className="card-note">observed path</span>
          </div>
          <AttackPath tactics={incident.tactics} techniques={incident.techniques} />
        </div>
      </div>

      <h2 className="section-title">Investigation timeline</h2>
      <div className="card">
        <div className="card-head">
          <h3 className="card-title">
            {incident.timeline.length} entries around this account, address and host
          </h3>
          <span className="card-note">ordered by event time · newest activity first in the window</span>
        </div>
        <Timeline items={incident.timeline} />
      </div>

      <h2 className="section-title">Contributing alerts</h2>
      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Detection</th>
              <th className="num">Risk</th>
              <th className="num">Events</th>
              <th>First seen</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {incident.alerts.map((alert) => (
              <tr key={alert.alert_id}>
                <td className="primary">
                  <Link href={`/detections/${alert.rule_id}`}>{alert.rule_title}</Link>
                  <div className="muted mono" style={{ fontSize: 11 }}>
                    {alert.rule_id} · {alert.rule_level}
                    {alert.is_building_block && " · correlation building block"}
                  </div>
                </td>
                <td className="num">{alert.risk_score}</td>
                <td className="num">{alert.occurrences}</td>
                <td>{dateTime(alert.first_seen)}</td>
                <td>
                  <StatusBadge status={alert.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="section-title">Discussion</h2>
      <div className="grid grid-2">
        <div className="card">
          <div className="card-head">
            <h3 className="card-title">Comments</h3>
            <span className="card-note">
              {threads.length === 0 ? "nothing yet" : `${threads.length} thread(s)`}
            </span>
          </div>
          <CommentThread
            threads={threads}
            busy={busy}
            onReply={(body, parentId) => postComment(body, parentId)}
          />
        </div>

        <div className="card">
          <div className="card-head">
            <h3 className="card-title">Watchers</h3>
            <button
              type="button"
              className="chart-toggle"
              disabled={busy}
              onClick={() => toggleWatch()}
            >
              {watching ? "Stop watching" : "Watch"}
            </button>
          </div>
          {watchers.length === 0 ? (
            <p className="empty">Nobody is watching this incident.</p>
          ) : (
            <div className="stack" style={{ gap: 8 }}>
              {watchers.map((watcher) => (
                <div key={watcher.user_id} className="spread">
                  <span style={{ fontSize: 13 }}>{watcher.email}</span>
                  <Tag
                    title={
                      watcher.reason === "mentioned"
                        ? "Added by an @mention"
                        : watcher.reason === "assigned"
                          ? "Added on assignment"
                          : "Chose to watch"
                    }
                  >
                    {watcher.reason}
                  </Tag>
                </div>
              ))}
            </div>
          )}
          <p className="card-note" style={{ marginTop: 12 }}>
            Watching is not owning. Being mentioned puts you on this list without
            making the incident yours.
          </p>
        </div>
      </div>

      <h2 className="section-title">Analyst actions</h2>
      <div className="grid grid-2">
        <div className="card">
          <div className="card-head">
            <h3 className="card-title">Workflow</h3>
            <span className="card-note">state machine</span>
          </div>
          <div className="row" style={{ gap: 8 }}>
            {allowed.length === 0 && <span className="muted">No transitions available.</span>}
            {allowed
              .filter((target) => target !== "waiting")
              .map((target) => (
                <button
                  key={target}
                  type="button"
                  className={target === "closed_false_positive" ? "button" : "button primary"}
                  disabled={busy}
                  onClick={() =>
                    act(
                      // The version we rendered goes with the write, so a
                      // concurrent edit is a 409 instead of a lost update.
                      () =>
                        api.transition(reference, target, undefined, {
                          expectedVersion: incident.version,
                        }),
                      `Moved to ${statusLabel(target)}.`,
                    )
                  }
                >
                  {statusLabel(target)}
                </button>
              ))}
          </div>

          {/* Parking an incident needs a reason and a wake-up time, otherwise
              it just disappears from the queue. */}
          {allowed.includes("waiting") && (
            <div className="stack" style={{ gap: 8, marginTop: 14 }}>
              <label htmlFor="waiting-reason" className="muted" style={{ fontSize: 12 }}>
                Park this incident
              </label>
              <div className="row" style={{ gap: 8 }}>
                <input
                  id="waiting-reason"
                  className="input"
                  placeholder="Waiting on what? (required)"
                  value={waitReason}
                  onChange={(event) => setWaitReason(event.target.value)}
                />
                <select
                  className="select"
                  value={waitHours}
                  onChange={(event) => setWaitHours(Number(event.target.value))}
                  aria-label="Come back in"
                >
                  <option value={4}>in 4 hours</option>
                  <option value={24}>tomorrow</option>
                  <option value={72}>in 3 days</option>
                </select>
                <button
                  type="button"
                  className="button"
                  disabled={busy || waitReason.trim().length < 3}
                  onClick={() =>
                    act(
                      () =>
                        api.transition(reference, "waiting", waitReason, {
                          waitingUntil: wakeUpAt(waitHours),
                          expectedVersion: incident.version,
                        }),
                      "Parked - it will come back to the queue when the timer expires.",
                    )
                  }
                >
                  Wait
                </button>
              </div>
            </div>
          )}

          <div className="row" style={{ gap: 8, marginTop: 14 }}>
            {incident.owner === session?.user?.email ? (
              <button
                type="button"
                className="button"
                disabled={busy}
                onClick={() =>
                  act(
                    () => api.unclaim(reference, "returned to the queue", incident.version),
                    "Returned to the queue.",
                  )
                }
              >
                Release
              </button>
            ) : (
              <button
                type="button"
                className="button"
                disabled={busy}
                onClick={() =>
                  act(() => api.claim(reference, incident.version), "Claimed - it is yours.")
                }
              >
                {incident.owner ? "Take over" : "Claim"}
              </button>
            )}
            {incident.owner ? <Tag>Owner {incident.owner}</Tag> : <Tag>unclaimed</Tag>}
            {incident.team_slug && <Tag title="Owning queue">queue {incident.team_slug}</Tag>}
            {incident.waiting_until && (
              <Tag title={incident.waiting_reason ?? undefined}>
                waiting until {dateTime(incident.waiting_until)}
              </Tag>
            )}
          </div>

          {/* Transfer demands a reason - the receiving team needs to know why. */}
          {teams.length > 0 && (
            <div className="stack" style={{ gap: 8, marginTop: 14 }}>
              <label htmlFor="transfer-team" className="muted" style={{ fontSize: 12 }}>
                Hand to another queue
              </label>
              <div className="row" style={{ gap: 8 }}>
                <select
                  id="transfer-team"
                  className="select"
                  value={transferTeam}
                  onChange={(event) => setTransferTeam(event.target.value)}
                >
                  <option value="">Select a queue...</option>
                  {teams
                    .filter((team) => team.slug !== incident.team_slug)
                    .map((team) => (
                      <option key={team.id} value={team.slug}>
                        {team.name}
                      </option>
                    ))}
                </select>
                <input
                  className="input"
                  placeholder="Why does it belong there? (required)"
                  value={transferReason}
                  onChange={(event) => setTransferReason(event.target.value)}
                />
                <button
                  type="button"
                  className="button"
                  disabled={busy || !transferTeam || transferReason.trim().length < 3}
                  onClick={() =>
                    act(
                      () =>
                        api.transfer(
                          reference,
                          transferTeam,
                          transferReason,
                          incident.version,
                        ),
                      `Transferred to ${transferTeam}.`,
                    )
                  }
                >
                  Transfer
                </button>
              </div>
            </div>
          )}

          <div className="form-field" style={{ marginTop: 16 }}>
            <label htmlFor="note">Add a comment</label>
            <textarea
              id="note"
              className="input"
              rows={3}
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="What did you check, and what did you conclude? Use @name to pull somebody in."
            />
          </div>
          <button
            type="button"
            className="button"
            disabled={busy || note.trim().length === 0}
            onClick={() => postComment(note)}
          >
            Save comment
          </button>
        </div>

        <div className="card">
          <div className="card-head">
            <h3 className="card-title">Response</h3>
            <span className="card-note">approval required</span>
          </div>

          <p className="notice" style={{ marginBottom: 12 }}>
            Playbooks act only on this deployment&apos;s isolated lab resources, run in dry-run
            mode by default, and cannot be approved by the analyst who requested them.
          </p>

          <div className="row" style={{ gap: 8 }}>
            <select
              className="select"
              value={playbook}
              onChange={(event) => setPlaybook(event.target.value)}
              aria-label="Playbook"
            >
              <option value="">Select a playbook…</option>
              {incident.suggested_playbooks.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.title}
                </option>
              ))}
            </select>
            <button
              type="button"
              className="button"
              disabled={busy || !playbook}
              onClick={() =>
                act(
                  () =>
                    api.requestAction(
                      reference,
                      playbook,
                      selectedPlaybook?.suggested_target ?? undefined,
                    ),
                  "Response requested - awaiting approval.",
                )
              }
            >
              Request
            </button>
          </div>

          {selectedPlaybook && (
            <p className="secondary" style={{ fontSize: 13, marginTop: 10 }}>
              {selectedPlaybook.description} Target:{" "}
              <span className="mono">{selectedPlaybook.suggested_target ?? "none"}</span>.
              Approvers: {selectedPlaybook.approver_roles.join(", ")}.
            </p>
          )}

          {incident.response_actions.length > 0 && (
            <table className="table" style={{ marginTop: 14 }}>
              <thead>
                <tr>
                  <th>Playbook</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {incident.response_actions.map((action) => (
                  <tr key={action.id}>
                    <td className="primary">{action.playbook}</td>
                    <td className="mono">{action.target ?? "-"}</td>
                    <td>
                      <StatusBadge status={action.status} />
                      {action.result?.message && (
                        <div className="muted" style={{ fontSize: 11 }}>
                          {action.result.message}
                          {action.dry_run ? " (dry run)" : ""}
                        </div>
                      )}
                    </td>
                    <td>
                      {action.status === "pending_approval" && (
                        <div className="row" style={{ gap: 6 }}>
                          <button
                            type="button"
                            className="button danger"
                            disabled={busy}
                            onClick={() =>
                              act(() => api.approveAction(action.id), "Playbook approved and run.")
                            }
                          >
                            Approve
                          </button>
                          <button
                            type="button"
                            className="button"
                            disabled={busy}
                            onClick={() =>
                              act(
                                () => api.rejectAction(action.id, "rejected from the console"),
                                "Playbook rejected.",
                              )
                            }
                          >
                            Reject
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <h2 className="section-title">Audit trail</h2>
      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {incident.audit.map((entry, index) => (
              <tr key={`${entry.time}-${index}`}>
                <td>{dateTime(entry.time)}</td>
                <td>{entry.actor}</td>
                <td className="primary mono" style={{ fontSize: 12 }}>
                  {entry.action}
                </td>
                <td>{entry.detail ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {incident.notes.length > 0 && (
        <>
          <h2 className="section-title">Notes</h2>
          <div className="card stack" style={{ gap: 12 }}>
            {incident.notes.map((entry) => (
              <div key={entry.id}>
                <div className="muted" style={{ fontSize: 12 }}>
                  {entry.author} · {dateTime(entry.time)}
                </div>
                <div>{entry.body}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}
