"use client";

import { riskBand, riskIcon } from "@/lib/format";

interface Props {
  score: number;
  showScale?: boolean;
  label?: string;
}

/**
 * Risk meter: the fill carries severity, the unfilled track is a lighter step
 * of the same blue ramp so the state reads across the whole bar. The numeric
 * score and the band name are always shown - colour never carries it alone.
 */
export function RiskMeter({ score, showScale = true, label = "Risk score" }: Props) {
  const clamped = Math.max(0, Math.min(100, score));
  const band = riskBand(clamped);

  return (
    <div>
      <div className="row spread" style={{ marginBottom: 6 }}>
        <span className="secondary" style={{ fontSize: 13 }}>
          {label}
        </span>
        <span style={{ fontWeight: 650, fontVariantNumeric: "tabular-nums" }}>
          {clamped} / 100
          <span className="muted" style={{ fontWeight: 500, marginLeft: 8 }}>
            {riskIcon(band)} {band}
          </span>
        </span>
      </div>
      <div
        className="meter"
        style={{ ["--meter-value" as string]: `${clamped}%` }}
        role="meter"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`${label}: ${clamped} of 100 (${band})`}
      >
        <div className={`meter-fill ${band}`} />
      </div>
      {showScale && (
        <div className="meter-scale">
          <span>0 informational</span>
          <span>30 low</span>
          <span>50 medium</span>
          <span>70 high</span>
          <span>90 critical</span>
        </div>
      )}
    </div>
  );
}
