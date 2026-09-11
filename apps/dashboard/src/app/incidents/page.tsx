"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { SeverityBadge, StatusBadge } from "@/components/Badge";
import { api, ApiError } from "@/lib/api";
import { relative } from "@/lib/format";
import type { IncidentSummary } from "@/lib/types";

const STATUSES = [
  "",
  "new",
  "triaged",
  "investigating",
  "contained",
  "resolved",
  "closed_false_positive",
];

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [status, setStatus] = useState("");
  const [minRisk, setMinRisk] = useState(0);
  const [openOnly, setOpenOnly] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .incidents({
        status: status || undefined,
        min_risk: minRisk || undefined,
        open_only: openOnly,
        limit: 100,
      })
      .then((rows) => {
        if (!cancelled) {
          setIncidents(rows);
          setError(null);
        }
      })
      .catch((exc) => {
        if (!cancelled) {
          setError(exc instanceof ApiError ? exc.message : "Could not load incidents.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [status, minRisk, openOnly]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Incidents</h1>
          <p className="page-subtitle">
            Correlated alert chains, ordered by risk. {incidents.length} shown.
          </p>
        </div>
      </div>

      {/* filters in one row above the content */}
      <div className="filters">
        <select
          className="select"
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          aria-label="Status"
        >
          {STATUSES.map((value) => (
            <option key={value || "any"} value={value}>
              {value ? value.replace(/_/g, " ") : "Any status"}
            </option>
          ))}
        </select>

        <select
          className="select"
          value={minRisk}
          onChange={(event) => setMinRisk(Number(event.target.value))}
          aria-label="Minimum risk"
        >
          <option value={0}>Any risk</option>
          <option value={30}>Low and above (30+)</option>
          <option value={50}>Medium and above (50+)</option>
          <option value={70}>High and above (70+)</option>
          <option value={90}>Critical only (90+)</option>
        </select>

        <label className="row" style={{ gap: 6, fontSize: 13 }}>
          <input
            type="checkbox"
            checked={openOnly}
            onChange={(event) => setOpenOnly(event.target.checked)}
          />
          Open only
        </label>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="card">
        {incidents.length === 0 ? (
          <p className="empty">
            No incidents match. Generate telemetry from the <Link href="/lab">lab page</Link>.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Principal</th>
                <th>Status</th>
                <th>Severity</th>
                <th className="num">Risk</th>
                <th className="num">Alerts</th>
                <th>ATT&amp;CK</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.incident_id}>
                  <td className="primary">
                    <Link href={`/incidents/${incident.key}`}>{incident.title}</Link>
                    <div className="muted mono" style={{ fontSize: 11 }}>
                      {incident.key}
                      {incident.scenario ? ` · ${incident.scenario}` : ""}
                    </div>
                  </td>
                  <td>{incident.principal ?? "-"}</td>
                  <td>
                    <StatusBadge status={incident.status} />
                  </td>
                  <td>
                    <SeverityBadge level={incident.severity} />
                  </td>
                  <td className="num">{incident.risk_score}</td>
                  <td className="num">{incident.alert_count}</td>
                  <td className="secondary" style={{ fontSize: 12 }}>
                    {incident.tactics.map((tactic) => tactic.name).join(" → ") || "-"}
                  </td>
                  <td>{relative(incident.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
