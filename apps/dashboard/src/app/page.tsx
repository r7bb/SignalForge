"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { SeverityBadge, StatusBadge } from "@/components/Badge";
import { BarChart, type BarDatum } from "@/components/BarChart";
import { RiskMeter } from "@/components/RiskMeter";
import { StatTile } from "@/components/StatTile";
import { api, ApiError } from "@/lib/api";
import { compact, humanSeconds, percent, relative } from "@/lib/format";
import type { IncidentSummary, Overview, SocReport, TacticCoverage } from "@/lib/types";

export default function OverviewPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [tactics, setTactics] = useState<TacticCoverage[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [soc, setSoc] = useState<SocReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [overviewData, mitre, openIncidents, socReport] = await Promise.all([
          api.overview(),
          api.mitre(),
          api.incidents({ open_only: true, limit: 8 }),
          // Newest addition, and the one most likely to be empty on a fresh
          // deployment - so a failure here must not blank the whole page.
          api.socMetrics(7).catch(() => null),
        ]);
        if (cancelled) return;
        setOverview(overviewData);
        setTactics(mitre.tactics);
        setIncidents(openIncidents);
        setSoc(socReport);
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

      {soc && soc.incidents_opened > 0 && (
        <>
          <h2 className="section-title">
            SOC performance · last {soc.window_days} days
          </h2>
          <div className="grid grid-4">
            <StatTile
              label="Mean time to acknowledge"
              value={humanSeconds(soc.mtta.mean_seconds)}
              note={
                soc.mtta.count
                  ? `p90 ${humanSeconds(soc.mtta.p90_seconds)} · ${soc.mtta.count} claimed`
                  : "nothing claimed yet"
              }
            />
            <StatTile
              label="Mean time to resolve"
              value={humanSeconds(soc.mttr.resolved.mean_seconds)}
              note={
                soc.mttr.false_positive.count
                  ? `false positives ${humanSeconds(soc.mttr.false_positive.mean_seconds)} (counted apart)`
                  : `${soc.mttr.resolved.count} resolved`
              }
            />
            <StatTile
              label="Acknowledge SLA met"
              value={percent(soc.sla.acknowledge.attainment)}
              accent={
                (soc.sla.acknowledge.attainment ?? 1) < 0.9
                  ? "var(--status-serious)"
                  : undefined
              }
              note={`${soc.sla.acknowledge.breached} breached of ${soc.sla.acknowledge.total}`}
            />
            <StatTile
              label="Reopen rate"
              value={percent(soc.reopen_rate)}
              accent={(soc.reopen_rate ?? 0) > 0.1 ? "var(--status-serious)" : undefined}
              note={`${soc.reopened} reopened of ${soc.analyst_closures} closed`}
            />
          </div>

          {soc.queues.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-head">
                <h3 className="card-title">Queue age</h3>
                <span className="card-note">
                  oldest unclaimed first - the leading indicator
                </span>
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Queue</th>
                    <th className="num">Open</th>
                    <th className="num">Unclaimed</th>
                    <th>Oldest unclaimed</th>
                  </tr>
                </thead>
                <tbody>
                  {soc.queues.map((queue) => (
                    <tr key={queue.team}>
                      <td className="primary">
                        <Link href="/queues">{queue.name ?? queue.team}</Link>
                        <div className="muted mono" style={{ fontSize: 11 }}>
                          {queue.team}
                        </div>
                      </td>
                      <td className="num">{queue.open}</td>
                      <td className="num">{queue.unclaimed}</td>
                      <td>{humanSeconds(queue.oldest_unclaimed_seconds)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {soc.by_team.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="card-head">
                <h3 className="card-title">By team</h3>
                <span className="card-note">mean, with p90 beside it</span>
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Team</th>
                    <th className="num">Claimed</th>
                    <th>MTTA</th>
                    <th>MTTR</th>
                  </tr>
                </thead>
                <tbody>
                  {soc.by_team.map((team) => (
                    <tr key={team.team}>
                      <td className="primary">{team.name ?? team.team}</td>
                      <td className="num">{team.mtta.count}</td>
                      <td>
                        {humanSeconds(team.mtta.mean_seconds)}
                        <span className="muted" style={{ fontSize: 11 }}>
                          {" "}
                          p90 {humanSeconds(team.mtta.p90_seconds)}
                        </span>
                      </td>
                      <td>{humanSeconds(team.mttr.mean_seconds)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

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
