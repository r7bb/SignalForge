"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Tag } from "@/components/Badge";
import { api, ApiError } from "@/lib/api";
import { titleCase } from "@/lib/format";
import type { LintReport, RuleSummary } from "@/lib/types";

export default function DetectionsPage() {
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [lint, setLint] = useState<LintReport | null>(null);
  const [kind, setKind] = useState("");
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      api.detections({ kind: kind || undefined, search: search || undefined }),
      api.lint(),
    ])
      .then(([ruleRows, lintReport]) => {
        if (!cancelled) {
          setRules(ruleRows);
          setLint(lintReport);
          setError(null);
        }
      })
      .catch((exc) => {
        if (!cancelled) {
          setError(exc instanceof ApiError ? exc.message : "Could not load detections.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [kind, search]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Detections</h1>
          <p className="page-subtitle">
            Detection-as-code: {rules.length} rules loaded from <span className="mono">detections/</span>
            {lint ? `, ${lint.tested_rules} with tests` : ""}
          </p>
        </div>
      </div>

      {lint && (
        <p className={lint.ok ? "notice" : "error"} style={{ marginBottom: 16 }}>
          Linter: {lint.ok ? "passing" : `${lint.errors.length} error(s)`} ·{" "}
          {lint.warnings.length} warning(s) · {lint.rule_count} detections ·{" "}
          {lint.correlation_count} correlations
        </p>
      )}

      <div className="filters">
        <select
          className="select"
          value={kind}
          onChange={(event) => setKind(event.target.value)}
          aria-label="Rule kind"
        >
          <option value="">All rules</option>
          <option value="detection">Detections</option>
          <option value="correlation">Correlations</option>
        </select>
        <input
          className="input"
          value={search}
          placeholder="Search title, id or description"
          onChange={(event) => setSearch(event.target.value)}
          aria-label="Search rules"
        />
      </div>

      {error && <p className="error">{error}</p>}

      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Kind</th>
              <th>Level</th>
              <th>Logsource</th>
              <th>ATT&amp;CK</th>
              <th className="num">Rev</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id}>
                <td className="primary">
                  <Link href={`/detections/${rule.id}`}>{rule.title}</Link>
                  <div className="muted mono" style={{ fontSize: 11 }}>
                    {rule.id}
                    {rule.name ? ` · ${rule.name}` : ""}
                  </div>
                </td>
                <td>
                  {rule.kind === "correlation" ? (
                    <Tag title={rule.correlation_rules.join(" → ")}>
                      {rule.correlation_type}
                    </Tag>
                  ) : rule.stateful ? (
                    <Tag title={rule.condition ?? undefined}>aggregation</Tag>
                  ) : (
                    <Tag>single event</Tag>
                  )}
                </td>
                <td>{titleCase(rule.level)}</td>
                <td className="secondary" style={{ fontSize: 12 }}>
                  {Object.entries(rule.logsource)
                    .map(([key, value]) => `${key}=${value}`)
                    .join(" ") || "-"}
                </td>
                <td className="secondary" style={{ fontSize: 12 }}>
                  {rule.tactics.map(titleCase).join(", ") || "-"}
                </td>
                <td className="num">{rule.revision ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {lint && lint.warnings.length > 0 && (
        <>
          <h2 className="section-title">Linter warnings</h2>
          <div className="card">
            <table className="table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Code</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {lint.warnings.map((warning, index) => (
                  <tr key={`${warning.path}-${index}`}>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {warning.rule_id ?? warning.path}
                    </td>
                    <td>{warning.code}</td>
                    <td>{warning.message}</td>
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
