"use client";

import { compact } from "@/lib/format";
import { Sparkline } from "./Sparkline";

interface Props {
  label: string;
  value: number | string;
  /** Optional signed delta against a named period. */
  delta?: { value: number; period: string; upIsGood?: boolean };
  /** Optional 12-point trend; the last point is drawn in the accent. */
  trend?: number[];
  /** Status accent for the value, when the tile is itself a severity readout. */
  accent?: string;
  note?: string;
  hero?: boolean;
}

/**
 * Stat tile: label · value · optional delta · optional sparkline.
 *
 * A count is a number, not a chart - so the tile is the form, and the
 * sparkline is a supporting 12-point trend rather than the main event.
 */
export function StatTile({ label, value, delta, trend, accent, note, hero }: Props) {
  const rendered = typeof value === "number" ? compact(value) : value;
  const deltaGood =
    delta === undefined
      ? false
      : delta.upIsGood === false
        ? delta.value <= 0
        : delta.value >= 0;

  return (
    <div className="card">
      <p className="tile-label">{label}</p>
      <div className={hero ? "tile-value hero" : "tile-value"} style={accent ? { color: accent } : undefined}>
        {rendered}
      </div>
      {(delta || note || trend) && (
        <div className="tile-foot">
          {delta && (
            <span className={`tile-delta ${deltaGood ? "good" : "bad"}`}>
              {delta.value >= 0 ? "+" : ""}
              {compact(delta.value)} vs {delta.period}
            </span>
          )}
          {note && <span>{note}</span>}
          {trend && trend.length > 1 && <Sparkline values={trend} width={84} height={22} />}
        </div>
      )}
    </div>
  );
}
