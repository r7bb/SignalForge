"use client";

import type { ReactNode } from "react";

import { humanSeconds, riskColor, riskIcon, statusLabel } from "@/lib/format";
import type { SlaState } from "@/lib/types";

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

/**
 * The SLA countdown on a queue row.
 *
 * Shows the *worse* of the two clocks, because that is the one that decides
 * whether this row needs attention. A met clock is deliberately quiet - the
 * chip exists to surface trouble, not to congratulate.
 */
export function SlaChip({ sla }: { sla?: SlaState | null }) {
  if (!sla || sla.state === "none") return <span className="muted">-</span>;

  const clock = sla.acknowledge.state === sla.state ? sla.acknowledge : sla.resolve;
  const label = clock.name === "acknowledge" ? "ack" : "resolve";

  if (sla.state === "breached") {
    return (
      <span className="badge" style={{ color: "var(--status-critical)" }}>
        <span className="badge-dot" style={{ background: "var(--status-critical)" }} />
        {label} over by {humanSeconds(clock.seconds_over)}
      </span>
    );
  }
  if (sla.state === "at_risk") {
    return (
      <span className="badge" style={{ color: "var(--status-high)" }}>
        <span className="badge-dot" style={{ background: "var(--status-high)" }} />
        {label} in {humanSeconds(clock.seconds_remaining)}
      </span>
    );
  }
  if (sla.state === "met") {
    return <span className="muted">met</span>;
  }
  return (
    <span className="secondary" style={{ fontSize: 12 }}>
      {label} in {humanSeconds(clock.seconds_remaining)}
    </span>
  );
}
