"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { Tag } from "@/components/Badge";
import { BarChart, type BarDatum } from "@/components/BarChart";
import { api, ApiError } from "@/lib/api";
import { titleCase } from "@/lib/format";

interface RuleTest {
  name?: string;
  kind?: string;
  expect?: string;
}

interface RuleDetail {
  id: string;
  name?: string | null;
  title: string;
  kind: string;
  level: string;
  status: string;
  description?: string | null;
  author?: string | null;
  logsource?: Record<string, string>;
  tactics: string[];
  techniques: string[];
  falsepositives: string[];
  condition?: string | null;
  correlation_type?: string | null;
  correlation_rules?: string[];
  timeframe_seconds?: number | null;
  source_path?: string | null;
  revision?: number | null;
  document?: Record<string, unknown>;
  searches?: Record<string, string[]>;
  tests?: RuleTest[];
  referenced_by?: Array<{ id: string; title: string; type: string }>;
  opensearch_query?: Record<string, unknown>;
}

export default function DetectionPage() {
  const params = useParams<{ ruleId: string }>();
  const ruleId = params.ruleId;

  const [rule, setRule] = useState<RuleDetail | null>(null);
  const [hunt, setHunt] = useState<{
    total: number;
    groups: Array<{ key: string; doc_count: number }>;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .detection(ruleId)
      .then((detail) => {
        setRule(detail as unknown as RuleDetail);
        setError(null);
      })
      .catch((exc) =>
        setError(exc instanceof ApiError ? exc.message : "Could not load the rule."),
      );
  }, [ruleId]);

  async function runHunt() {
    setBusy(true);
    try {
      const result = await api.retroHunt(ruleId, "now-30d");
      setHunt({ total: result.total, groups: result.groups });
      setError(null);
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Retro-hunt failed.");
    } finally {
      setBusy(false);
    }
  }

  if (!rule) {
    return error ? <p className="error">{error}</p> : <p className="empty">Loading rule…</p>;
  }

  const testCounts = (rule.tests ?? []).reduce<Record<string, number>>((acc, test) => {
    const kind = test.kind ?? "unknown";
    acc[kind] = (acc[kind] ?? 0) + 1;
    return acc;
  }, {});

  const huntGroups: BarDatum[] = (hunt?.groups ?? []).map((bucket) => ({
    label: String(bucket.key),
    value: bucket.doc_count,
  }));

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{rule.title}</h1>
          <p className="page-subtitle mono">
            {rule.id}
            {rule.name ? ` · ${rule.name}` : ""} · revision {rule.revision ?? 1}
          </p>
        </div>
        <div className="row" style={{ gap: 8 }}>
          <Tag>{titleCase(rule.level)}</Tag>
          <Tag>{rule.status}</Tag>
          <Tag>{rule.kind}</Tag>
        </div>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="grid grid-2">
        <div className="card">
          <div className="card-head">
            <h2 className="card-title">Definition</h2>
            {rule.source_path && <span className="card-note mono">{rule.source_path}</span>}
          </div>
          <p className="secondary" style={{ marginTop: 0 }}>
            {rule.description ?? "No description."}
          </p>
          <dl className="kv">
            <dt>Author</dt>
            <dd>{rule.author ?? "-"}</dd>
            <dt>Logsource</dt>
            <dd className="mono">
              {Object.entries(rule.logsource ?? {})
                .map(([key, value]) => `${key}=${value}`)
                .join(" ") || "-"}
            </dd>
            {rule.condition && (
              <>
                <dt>Condition</dt>
                <dd className="mono">{rule.condition}</dd>
              </>
            )}
            {rule.correlation_type && (
              <>
                <dt>Correlation</dt>
                <dd className="mono">
                  {rule.correlation_type}: {(rule.correlation_rules ?? []).join(" → ")}
                </dd>
              </>
            )}
            {rule.timeframe_seconds && (
              <>
                <dt>Window</dt>
                <dd>{rule.timeframe_seconds} s</dd>
              </>
            )}
            <dt>ATT&amp;CK</dt>
            <dd>
              {rule.tactics.map(titleCase).join(", ") || "-"}
              {rule.techniques.length > 0 && (
                <span className="muted"> · {rule.techniques.join(", ")}</span>
              )}
            </dd>
          </dl>
        </div>

        <div className="card">
          <div className="card-head">
            <h2 className="card-title">Tests</h2>
            <span className="card-note">positive / negative / false-positive</span>
          </div>
          {rule.tests && rule.tests.length > 0 ? (
            <>
              <div className="row" style={{ gap: 8, marginBottom: 12 }}>
                {["positive", "negative", "false_positive"].map((kind) => (
                  <Tag key={kind}>
                    {titleCase(kind)}: {testCounts[kind] ?? 0}
                  </Tag>
                ))}
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Case</th>
                    <th>Kind</th>
                    <th>Expect</th>
                  </tr>
                </thead>
                <tbody>
                  {rule.tests.map((test, index) => (
                    <tr key={`${test.name}-${index}`}>
                      <td className="primary">{test.name ?? "unnamed"}</td>
                      <td>{titleCase(test.kind ?? "-")}</td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {test.expect ?? "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <p className="empty">No test file for this rule.</p>
          )}

          {rule.falsepositives.length > 0 && (
            <>
              <h3 className="card-title" style={{ marginTop: 16 }}>
                Documented false positives
              </h3>
              <ul className="secondary" style={{ fontSize: 13, paddingLeft: 18 }}>
                {rule.falsepositives.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>

      {rule.referenced_by && rule.referenced_by.length > 0 && (
        <>
          <h2 className="section-title">Used by correlations</h2>
          <div className="card row" style={{ gap: 8 }}>
            {rule.referenced_by.map((correlation) => (
              <Tag key={correlation.id} title={correlation.type}>
                {correlation.title}
              </Tag>
            ))}
          </div>
        </>
      )}

      {rule.kind === "detection" && (
        <>
          <h2 className="section-title">Retro-hunt</h2>
          <div className="card">
            <div className="card-head">
              <h3 className="card-title">Run this detection over the last 30 days</h3>
              <button type="button" className="button" onClick={runHunt} disabled={busy}>
                {busy ? "Hunting…" : "Run"}
              </button>
            </div>
            {hunt ? (
              <>
                <p className="secondary">{hunt.total} matching events.</p>
                <BarChart
                  data={huntGroups}
                  color="var(--series-2)"
                  valueLabel="events per group"
                  emptyMessage="No grouped results (this rule is not an aggregation)."
                />
              </>
            ) : (
              <p className="muted" style={{ fontSize: 13 }}>
                The rule is compiled to an OpenSearch query and run against stored events.
              </p>
            )}
          </div>
        </>
      )}

      <h2 className="section-title">Rule document</h2>
      <div className="card">
        <pre
          className="mono"
          style={{ margin: 0, whiteSpace: "pre-wrap", fontSize: 12, color: "var(--text-secondary)" }}
        >
          {JSON.stringify(rule.document ?? {}, null, 2)}
        </pre>
      </div>
    </>
  );
}
