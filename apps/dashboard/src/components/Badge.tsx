"use client";

import type { ReactNode } from "react";

import { riskColor, riskIcon, statusLabel } from "@/lib/format";

interface SeverityBadgeProps {
  level: string;
  score?: number;
}

/**
 * Severity badge: dot + icon + label. A reserved status colour never carries
 * meaning on its own, so the word is always present.
 */
export function SeverityBadge({ level, score }: SeverityBadgeProps) {
  return (
    <span className="badge" title={score !== undefined ? `Risk ${score}/100` : undefined}>
      <span className="badge-dot" style={{ background: riskColor(level) }} />
      <span className="badge-icon" aria-hidden="true">
        {riskIcon(level)}
      </span>
      {statusLabel(level)}
      {score !== undefined && (
        <span className="muted" style={{ fontVariantNumeric: "tabular-nums" }}>
          {score}
        </span>
      )}
    </span>
  );
}

const STATUS_COLORS: Record<string, string> = {
  new: "var(--series-1)",
  triaged: "var(--series-4)",
  investigating: "var(--series-2)",
  contained: "var(--series-7)",
  resolved: "var(--status-good)",
  closed_false_positive: "var(--text-muted)",
  correlated: "var(--series-7)",
  suppressed: "var(--text-muted)",
  false_positive: "var(--text-muted)",
  pending_approval: "var(--series-4)",
  approved: "var(--series-1)",
  rejected: "var(--text-muted)",
  executed: "var(--status-good)",
  failed: "var(--status-critical)",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className="badge">
      <span
        className="badge-dot"
        style={{ background: STATUS_COLORS[status] ?? "var(--text-muted)" }}
      />
      {statusLabel(status)}
    </span>
  );
}

export function Tag({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <span className="badge" title={title}>
      {children}
    </span>
  );
}
