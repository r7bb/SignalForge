"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { SeverityBadge, StatusBadge } from "@/components/Badge";
import { api, ApiError } from "@/lib/api";
import { relative } from "@/lib/format";
import type { AlertSummary } from "@/lib/types";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [minRisk, setMinRisk] = useState(0);
  const [hours, setHours] = useState(24);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .alerts({ min_risk: minRisk || undefined, hours, limit: 200 })
      .then((rows) => {
        if (!cancelled) {
          setAlerts(rows);
          setError(null);
        }
      })
      .catch((exc) => {
        if (!cancelled) {
          setError(exc instanceof ApiError ? exc.message : "Could not load alerts.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [minRisk, hours]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">
            Deduplicated by rule and entity - repeats increment the occurrence count.
          </p>
        </div>
      </div>

      <div className="filters">
        <select
          className="select"
          value={hours}
          onChange={(event) => setHours(Number(event.target.value))}
          aria-label="Time range"
        >
          <option value={1}>Last hour</option>
          <option value={24}>Last 24 hours</option>
          <option value={168}>Last 7 days</option>
          <option value={720}>Last 30 days</option>
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
      </div>

      {error && <p className="error">{error}</p>}

      <div className="card">
        {alerts.length === 0 ? (
          <p className="empty">No alerts in this window.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Detection</th>
                <th>Principal</th>
                <th>Source</th>
                <th>Severity</th>
                <th className="num">Risk</th>
                <th className="num">Count</th>
                <th>Status</th>
                <th>Last seen</th>
                <th>Incident</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.alert_id}>
                  <td className="primary">
                    <Link href={`/detections/${alert.rule_id}`}>{alert.rule_title}</Link>
                    <div className="muted mono" style={{ fontSize: 11 }}>
                      {alert.rule_id}
                    </div>
                  </td>
                  <td>{alert.principal ?? "-"}</td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {alert.source_ip ?? "-"}
                    {alert.hostname ? ` · ${alert.hostname}` : ""}
                  </td>
                  <td>
                    <SeverityBadge level={alert.risk_level} />
                  </td>
                  <td className="num">{alert.risk_score}</td>
                  <td className="num">{alert.occurrences}</td>
                  <td>
                    <StatusBadge status={alert.status} />
                  </td>
                  <td>{relative(alert.last_seen)}</td>
                  <td>
                    {alert.incident_id ? (
                      <Link href={`/incidents/${alert.incident_id}`}>open</Link>
                    ) : (
                      <span className="muted">-</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
