"use client";

import { useEffect, useState } from "react";

import { SeverityBadge, Tag } from "@/components/Badge";
import { StatTile } from "@/components/StatTile";
import { api, ApiError } from "@/lib/api";
import { dateTime } from "@/lib/format";
import type { SupplyChainApp, SupplyChainFinding, VulnerabilityImpact } from "@/lib/types";

export default function SupplyChainPage() {
  const [apps, setApps] = useState<SupplyChainApp[]>([]);
  const [findings, setFindings] = useState<SupplyChainFinding[]>([]);
  const [impact, setImpact] = useState<VulnerabilityImpact | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.applications(), api.findings()])
      .then(([appsResponse, findingsResponse]) => {
        setApps(appsResponse.applications);
        setFindings(findingsResponse.findings);
        setError(null);
      })
      .catch((exc) =>
        setError(exc instanceof ApiError ? exc.message : "Could not load supply-chain data."),
      );
  }, []);

  async function showImpact(vulnId: string) {
    try {
      setImpact(await api.impact(vulnId));
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Could not load the impact view.");
    }
  }

  const totalComponents = apps.reduce((sum, app) => sum + app.components, 0);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Software supply chain</h1>
          <p className="page-subtitle">
            SBOM inventory and vulnerability impact - which applications actually contain the
            affected component.
          </p>
        </div>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="grid grid-3">
        <StatTile label="Applications" value={apps.length} />
        <StatTile label="Components tracked" value={totalComponents} />
        <StatTile
          label="Open findings"
          value={findings.length}
          accent={findings.length > 0 ? "var(--status-serious)" : undefined}
        />
      </div>

      <h2 className="section-title">Applications</h2>
      <div className="card">
        {apps.length === 0 ? (
          <p className="empty">
            No SBOMs ingested. POST a CycloneDX or SPDX document to{" "}
            <span className="mono">/api/v1/sbom/ingest</span>.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Application</th>
                <th>Environment</th>
                <th>Criticality</th>
                <th className="num">Components</th>
                <th className="num">Open findings</th>
                <th>Format</th>
                <th>Ingested</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((app) => (
                <tr key={app.id}>
                  <td className="primary">{app.name}</td>
                  <td>{app.environment}</td>
                  <td>
                    <SeverityBadge level={app.criticality} />
                  </td>
                  <td className="num">{app.components}</td>
                  <td className="num">{app.open_vulnerabilities}</td>
                  <td>{app.sbom_format ?? "-"}</td>
                  <td>{app.ingested_at ? dateTime(app.ingested_at) : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <h2 className="section-title">Open findings</h2>
      <div className="card">
        {findings.length === 0 ? (
          <p className="empty">No affected components.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Advisory</th>
                <th>Component</th>
                <th>Application</th>
                <th>Severity</th>
                <th className="num">CVSS</th>
                <th>Fixed in</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {findings.map((finding, index) => (
                <tr key={`${finding.vuln_id}-${finding.application}-${index}`}>
                  <td className="primary mono" style={{ fontSize: 13 }}>
                    {finding.vuln_id}
                    {finding.title && (
                      <div className="muted" style={{ fontSize: 11 }}>
                        {finding.title}
                      </div>
                    )}
                  </td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {finding.component}@{finding.version}
                    {finding.direct ? "" : " (transitive)"}
                  </td>
                  <td>{finding.application}</td>
                  <td>
                    <SeverityBadge level={finding.severity} />
                  </td>
                  <td className="num">{finding.cvss_score ?? "-"}</td>
                  <td className="mono" style={{ fontSize: 12 }}>
                    {finding.fixed_version ?? "-"}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="chart-toggle"
                      onClick={() => showImpact(finding.vuln_id)}
                    >
                      Impact
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {impact && (
        <>
          <h2 className="section-title">Impact of {impact.vuln_id}</h2>
          <div className="card">
            <div className="card-head">
              <div>
                <h3 className="card-title">{impact.title ?? impact.vuln_id}</h3>
                <p className="card-note mono">
                  {impact.package} {impact.affected_range}
                  {impact.fixed_version ? ` · fixed in ${impact.fixed_version}` : ""}
                </p>
              </div>
              <SeverityBadge level={impact.severity} />
            </div>
            <table className="table">
              <thead>
                <tr>
                  <th>Application</th>
                  <th>Status</th>
                  <th>Installed</th>
                  <th>Environment</th>
                </tr>
              </thead>
              <tbody>
                {impact.applications.map((row) => (
                  <tr key={row.application}>
                    <td className="primary">{row.application}</td>
                    <td>
                      {row.status === "affected" ? (
                        <SeverityBadge level="critical" />
                      ) : (
                        <Tag>{row.status.replace(/_/g, " ")}</Tag>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {row.findings.map((finding) => finding.version).join(", ") || "-"}
                    </td>
                    <td>{row.environment}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
