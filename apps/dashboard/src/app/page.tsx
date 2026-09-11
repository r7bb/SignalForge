"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { SeverityBadge, StatusBadge } from "@/components/Badge";
import { BarChart, type BarDatum } from "@/components/BarChart";
import { RiskMeter } from "@/components/RiskMeter";
import { StatTile } from "@/components/StatTile";
import { api, ApiError } from "@/lib/api";
import { compact, relative } from "@/lib/format";
import type { IncidentSummary, Overview, TacticCoverage } from "@/lib/types";

export default function OverviewPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [tactics, setTactics] = useState<TacticCoverage[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [overviewData, mitre, openIncidents] = await Promise.all([
          api.overview(),
          api.mitre(),
          api.incidents({ open_only: true, limit: 8 }),
        ]);
        if (cancelled) return;
        setOverview(overviewData);
        setTactics(mitre.tactics);
        setIncidents(openIncidents);
        setError(null);
      } catch (exc) {
        if (!cancelled) {
          setError(exc instanceof ApiError ? exc.message : "Could not load the overview.");
        }
      }
    }

    load();
    const timer = window.setInterval(load, 15_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const coverage: BarDatum[] = tactics
    .filter((tactic) => tactic.rules > 0 || tactic.incidents > 0)
    .map((tactic) => ({
      label: tactic.name,
      value: tactic.rules,
      secondary: { label: "incidents", value: tactic.incidents },
    }));

  const eventClasses: BarDatum[] = Object.entries(overview?.events_by_class ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([label, value]) => ({ label, value }));

  const topIncident = incidents[0];

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Security overview</h1>
          <p className="page-subtitle">
            {overview
              ? `Updated ${relative(overview.generated_at)} · mean detection latency ${overview.mean_detection_latency_ms.toFixed(2)} ms`
              : "Loading…"}
          </p>
        </div>
        <Link href="/lab" className="button">
          Generate lab telemetry
        </Link>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="grid grid-4">
        <StatTile
          label="Critical alerts"
          value={overview?.critical_alerts ?? 0}
          accent="var(--status-critical)"
          note="risk 90-100"
        />
        <StatTile
          label="High alerts"
          value={overview?.high_alerts ?? 0}
          accent="var(--status-serious)"
          note="risk 70-89"
        />
        <StatTile
          label="Events today"
          value={overview?.events_today ?? 0}
          note="since midnight UTC"
        />
        <StatTile
          label="Open incidents"
          value={overview?.open_incidents ?? 0}
          note={`${compact(overview?.incidents_total ?? 0)} total`}
        />
      </div>

      {topIncident && (
        <>
          <h2 className="section-title">Highest-risk open incident</h2>
          <div className="card">
            <div className="card-head">
              <div>
                <h3 className="card-title">
                  <Link href={`/incidents/${topIncident.key}`}>
                    {topIncident.key} · {topIncident.title}
                  </Link>
                </h3>
                <p className="card-note">
                  {topIncident.principal ?? "unattributed"}
                  {topIncident.source_ips[0] ? ` · ${topIncident.source_ips[0]}` : ""} ·{" "}
                  {topIncident.alert_count} alerts · {topIncident.evidence_count} events
                </p>
              </div>
              <div className="row" style={{ gap: 8 }}>
                <StatusBadge status={topIncident.status} />
                <SeverityBadge level={topIncident.severity} />
              </div>
            </div>
            <RiskMeter score={topIncident.risk_score} />
          </div>
        </>
      )}

      <h2 className="section-title">Detection coverage &amp; activity</h2>
      <div className="grid grid-2">
        <div className="card">
          <div className="card-head">
            <h3 className="card-title">Rules per ATT&amp;CK tactic</h3>
            <span className="card-note">kill-chain order</span>
          </div>
          <BarChart
            data={coverage}
            valueLabel="rules"
            emptyMessage="No rules loaded."
          />
        </div>

        <div className="card">
          <div className="card-head">
            <h3 className="card-title">Events today by OCSF class</h3>
            <span className="card-note">normalized events</span>
          </div>
          <BarChart
            data={eventClasses}
            color="var(--series-3)"
            valueLabel="events"
            emptyMessage="No events ingested yet - try the lab page."
          />
        </div>
      </div>

      <h2 className="section-title">Noisiest detections</h2>
      <div className="card">
        {overview && overview.top_rules.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Rule</th>
                <th className="num">Alerts</th>
                <th className="num">Occurrences</th>
                <th className="num">Peak risk</th>
              </tr>
            </thead>
            <tbody>
              {overview.top_rules.map((rule) => (
                <tr key={rule.rule_id}>
                  <td className="primary">
                    <Link href={`/detections/${rule.rule_id}`}>{rule.rule_title}</Link>
                    <div className="muted mono" style={{ fontSize: 11 }}>
                      {rule.rule_id}
                    </div>
                  </td>
                  <td className="num">{rule.alerts}</td>
                  <td className="num">{rule.occurrences}</td>
                  <td className="num">{rule.max_risk}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="empty">No alerts yet.</p>
        )}
      </div>

      {overview && (overview.supply_chain.open_findings ?? 0) > 0 && (
        <>
          <h2 className="section-title">Software supply chain</h2>
          <div className="grid grid-3">
            <StatTile label="Applications" value={overview.supply_chain.applications ?? 0} />
            <StatTile
              label="Components tracked"
              value={overview.supply_chain.components ?? 0}
            />
            <StatTile
              label="Open findings"
              value={overview.supply_chain.open_findings ?? 0}
              accent="var(--status-serious)"
              note={(overview.supply_chain.affected_applications ?? []).join(", ")}
            />
          </div>
        </>
      )}
    </>
  );
}
