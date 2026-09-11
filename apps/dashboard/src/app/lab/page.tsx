"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Tag } from "@/components/Badge";
import { api, ApiError } from "@/lib/api";
import { titleCase } from "@/lib/format";

interface Scenario {
  name: string;
  title: string;
  description: string;
  expected_detections: string[];
}

interface SimulationResult {
  scenario: string;
  records: number;
  events: number;
  alerts: number;
  incidents: Array<{ key: string; title: string; risk_score: number }>;
  detections_fired: string[];
  expected_not_fired: string[];
}

export default function LabPage() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .scenarios()
      .then((response) => setScenarios(response.scenarios))
      .catch((exc) =>
        setError(exc instanceof ApiError ? exc.message : "Could not load scenarios."),
      );
  }, []);

  async function run(scenario?: string, normalEvents = 0) {
    setRunning(scenario ?? "baseline");
    setError(null);
    try {
      setResult(await api.simulate(scenario, normalEvents));
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Simulation failed.");
    } finally {
      setRunning(null);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Lab telemetry</h1>
          <p className="page-subtitle">
            Seeded, benign reproductions of suspicious telemetry shapes, replayed through the
            live pipeline.
          </p>
        </div>
        <button
          type="button"
          className="button"
          disabled={running !== null}
          onClick={() => run(undefined, 400)}
        >
          {running === "baseline" ? "Generating…" : "Generate 400 baseline events"}
        </button>
      </div>

      <p className="notice" style={{ marginBottom: 16 }}>
        Nothing here attacks anything: each scenario emits log records into SignalForge&apos;s own
        ingestion path so the detections can be exercised without touching a real system.
      </p>

      {error && <p className="error">{error}</p>}

      {result && (
        <div className="card" style={{ marginBottom: 20 }}>
          <div className="card-head">
            <h2 className="card-title">Last run: {titleCase(result.scenario)}</h2>
            <span className="card-note">
              {result.records} records → {result.events} events → {result.alerts} alerts
            </span>
          </div>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            {result.detections_fired.map((ruleId) => (
              <Tag key={ruleId}>{ruleId}</Tag>
            ))}
            {result.detections_fired.length === 0 && (
              <span className="muted">No detections fired.</span>
            )}
          </div>
          {result.expected_not_fired.length > 0 && (
            <p className="secondary" style={{ fontSize: 13 }}>
              Expected but did not fire: {result.expected_not_fired.join(", ")} (some stages need
              the baseline window to warm up - run the scenario twice).
            </p>
          )}
          {result.incidents.length > 0 && (
            <table className="table" style={{ marginTop: 10 }}>
              <thead>
                <tr>
                  <th>Incident</th>
                  <th className="num">Risk</th>
                </tr>
              </thead>
              <tbody>
                {result.incidents.map((incident) => (
                  <tr key={incident.key}>
                    <td className="primary">
                      <Link href={`/incidents/${incident.key}`}>
                        {incident.key} · {incident.title}
                      </Link>
                    </td>
                    <td className="num">{incident.risk_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <div className="grid grid-2">
        {scenarios.map((scenario) => (
          <div className="card" key={scenario.name}>
            <div className="card-head">
              <h3 className="card-title">{scenario.title}</h3>
              <button
                type="button"
                className="button"
                disabled={running !== null}
                onClick={() => run(scenario.name)}
              >
                {running === scenario.name ? "Running…" : "Replay"}
              </button>
            </div>
            <p className="secondary" style={{ fontSize: 13, marginTop: 0 }}>
              {scenario.description}
            </p>
            <div className="row" style={{ gap: 6 }}>
              {scenario.expected_detections.map((ruleId) => (
                <Tag key={ruleId}>{ruleId}</Tag>
              ))}
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
