"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { AttackPath } from "@/components/AttackPath";
import { SeverityBadge, StatusBadge, Tag } from "@/components/Badge";
import { RiskMeter } from "@/components/RiskMeter";
import { Timeline } from "@/components/Timeline";
import { api, ApiError } from "@/lib/api";
import { dateTime, duration, statusLabel } from "@/lib/format";
import type { IncidentDetail } from "@/lib/types";

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

  const load = useCallback(async () => {
    try {
      const [detail, transitions] = await Promise.all([
        api.incident(reference),
        api.allowedTransitions(reference),
      ]);
      setIncident(detail);
      setAllowed(transitions.allowed);
      setError(null);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Could not load the incident.");
    }
  }, [reference]);

  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>, successMessage: string) {
    setBusy(true);
    setMessage(null);
    try {
      await fn();
      setMessage(successMessage);
      await load();
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Action failed.");
    } finally {
      setBusy(false);
    }
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

      <h2 className="section-title">Analyst actions</h2>
      <div className="grid grid-2">
        <div className="card">
          <div className="card-head">
            <h3 className="card-title">Workflow</h3>
            <span className="card-note">state machine</span>
          </div>
          <div className="row" style={{ gap: 8 }}>
            {allowed.length === 0 && <span className="muted">No transitions available.</span>}
            {allowed.map((target) => (
              <button
                key={target}
                type="button"
                className={target === "closed_false_positive" ? "button" : "button primary"}
                disabled={busy}
                onClick={() =>
                  act(
                    () => api.transition(reference, target),
                    `Moved to ${statusLabel(target)}.`,
                  )
                }
              >
                {statusLabel(target)}
              </button>
            ))}
          </div>

          <div className="row" style={{ gap: 8, marginTop: 14 }}>
            <button
              type="button"
              className="button"
              disabled={busy}
              onClick={() => act(() => api.assign(reference, "me"), "Assigned to you.")}
            >
              Assign to me
            </button>
            {incident.owner && <Tag>Owner {incident.owner}</Tag>}
          </div>

          <div className="form-field" style={{ marginTop: 16 }}>
            <label htmlFor="note">Add a note</label>
            <textarea
              id="note"
              className="input"
              rows={3}
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="What did you check, and what did you conclude?"
            />
          </div>
          <button
            type="button"
            className="button"
            disabled={busy || note.trim().length === 0}
            onClick={() =>
              act(() => api.addNote(reference, note).then(() => setNote("")), "Note added.")
            }
          >
            Save note
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
