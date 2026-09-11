"use client";

import { useState } from "react";

export interface BarDatum {
  label: string;
  value: number;
  /** Optional secondary number shown in the tooltip and the table view. */
  secondary?: { label: string; value: number };
}

interface Props {
  data: BarDatum[];
  /** Single series, so no legend: the card title names what is plotted. */
  color?: string;
  valueLabel?: string;
  emptyMessage?: string;
}

const ROW_HEIGHT = 30;
const BAR_HEIGHT = 16; // <= 24px, leftover band is air
const LABEL_WIDTH = 132;
const VALUE_GUTTER = 44;

/**
 * Horizontal bars for magnitude by category (ATT&CK tactic coverage, rule
 * volume). 4px rounded data-end, square at the baseline, a 2px surface gap
 * between neighbours, values direct-labelled at the tip, and a table view for
 * anyone who cannot use the chart.
 */
export function BarChart({
  data,
  color = "var(--series-1)",
  valueLabel = "value",
  emptyMessage = "No data yet.",
}: Props) {
  const [showTable, setShowTable] = useState(false);
  const [hover, setHover] = useState<{ x: number; y: number; datum: BarDatum } | null>(null);

  if (data.length === 0) {
    return <p className="empty">{emptyMessage}</p>;
  }

  const max = Math.max(...data.map((item) => item.value), 1);
  const height = data.length * ROW_HEIGHT;
  const plotWidth = 460;
  const trackWidth = plotWidth - LABEL_WIDTH - VALUE_GUTTER;

  return (
    <div>
      <div className="row spread" style={{ marginBottom: 8 }}>
        <span className="card-note">{valueLabel}</span>
        <button
          type="button"
          className="chart-toggle"
          aria-pressed={showTable}
          onClick={() => setShowTable((previous) => !previous)}
        >
          {showTable ? "Chart view" : "Table view"}
        </button>
      </div>

      {showTable ? (
        <table className="table">
          <thead>
            <tr>
              <th>Category</th>
              <th className="num">{valueLabel}</th>
              {data[0].secondary && <th className="num">{data[0].secondary.label}</th>}
            </tr>
          </thead>
          <tbody>
            {data.map((item) => (
              <tr key={item.label}>
                <td className="primary">{item.label}</td>
                <td className="num">{item.value}</td>
                {item.secondary && <td className="num">{item.secondary.value}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <svg
          className="chart-svg"
          viewBox={`0 0 ${plotWidth} ${height}`}
          role="img"
          aria-label={`${valueLabel} by category`}
        >
          {data.map((item, index) => {
            const y = index * ROW_HEIGHT;
            const barY = y + (ROW_HEIGHT - BAR_HEIGHT) / 2;
            const width = Math.max((item.value / max) * trackWidth, item.value > 0 ? 3 : 0);
            return (
              <g
                key={item.label}
                onMouseMove={(event) =>
                  setHover({ x: event.clientX, y: event.clientY, datum: item })
                }
                onMouseLeave={() => setHover(null)}
              >
                {/* hit target is taller than the mark */}
                <rect x={0} y={y} width={plotWidth} height={ROW_HEIGHT} fill="transparent" />
                <text
                  className="chart-label"
                  x={LABEL_WIDTH - 10}
                  y={y + ROW_HEIGHT / 2}
                  textAnchor="end"
                  dominantBaseline="middle"
                >
                  {item.label}
                </text>
                {/* 2px surface gap between neighbours comes from the row padding */}
                <rect
                  x={LABEL_WIDTH}
                  y={barY}
                  width={width}
                  height={BAR_HEIGHT}
                  fill={color}
                  rx={4}
                />
                {/* square off the baseline end of the rounded rect */}
                {width > 4 && (
                  <rect x={LABEL_WIDTH} y={barY} width={4} height={BAR_HEIGHT} fill={color} />
                )}
                <text
                  className="chart-value"
                  x={LABEL_WIDTH + width + 8}
                  y={y + ROW_HEIGHT / 2}
                  dominantBaseline="middle"
                >
                  {item.value}
                </text>
              </g>
            );
          })}
          <line
            x1={LABEL_WIDTH}
            y1={0}
            x2={LABEL_WIDTH}
            y2={height}
            stroke="var(--baseline)"
            strokeWidth={1}
          />
        </svg>
      )}

      {hover && (
        <div className="tooltip" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          <strong>{hover.datum.label}</strong>
          <div className="tooltip-row">
            <span className="muted">{valueLabel}</span>
            <span>{hover.datum.value}</span>
          </div>
          {hover.datum.secondary && (
            <div className="tooltip-row">
              <span className="muted">{hover.datum.secondary.label}</span>
              <span>{hover.datum.secondary.value}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
