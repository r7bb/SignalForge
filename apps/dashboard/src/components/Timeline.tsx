"use client";

import { useState } from "react";

import { dateTime, timeOfDay } from "@/lib/format";
import type { TimelineItem } from "@/lib/types";

interface Props {
  items: TimelineItem[];
  emptyMessage?: string;
}

/** Kind -> mark colour. Alerts and responses use reserved status colours. */
function dotColor(item: TimelineItem): string {
  if (item.kind === "alert") {
    switch (item.severity) {
      case "critical":
        return "var(--status-critical)";
      case "high":
        return "var(--status-serious)";
      case "medium":
        return "var(--status-warning)";
      default:
        return "var(--series-1)";
    }
  }
  if (item.kind === "response") return "var(--series-7)";
  if (item.kind === "note") return "var(--series-3)";
  if (item.kind === "status") return "var(--series-4)";
  return item.outcome === "Failure" ? "var(--status-serious)" : "var(--series-1)";
}

function kindLabel(item: TimelineItem): string {
  if (item.kind === "alert") return "Alert";
  if (item.kind === "response") return "Response";
  if (item.kind === "note") return "Note";
  if (item.kind === "status") return "Status";
  return item.class_name ?? "Event";
}

/**
 * The investigation timeline: one row per event/alert/response, ordered by
 * *event* time so late-arriving logs land in the right slot. Every row carries
 * its kind as text - the dot colour is a supporting cue, not the only one.
 */
export function Timeline({ items, emptyMessage = "No activity in this window." }: Props) {
  const [hover, setHover] = useState<{ x: number; y: number; item: TimelineItem } | null>(null);

  if (items.length === 0) {
    return <p className="empty">{emptyMessage}</p>;
  }

  return (
    <>
      <ol className="timeline">
        {items.map((item, index) => (
          <li
            className="timeline-item"
            key={`${item.time}-${index}`}
            onMouseMove={(event) => setHover({ x: event.clientX, y: event.clientY, item })}
            onMouseLeave={() => setHover(null)}
          >
            <time className="timeline-time" dateTime={item.time} title={dateTime(item.time)}>
              {timeOfDay(item.time)}
            </time>
            <span className="timeline-dot-wrap">
              <span className="timeline-dot" style={{ background: dotColor(item) }} />
            </span>
            <div>
              <div className="timeline-title">
                <span className="muted" style={{ fontSize: 11, marginRight: 6 }}>
                  {kindLabel(item)}
                </span>
                {item.title}
              </div>
              {item.detail && <div className="timeline-detail">{item.detail}</div>}
              <div className="timeline-meta">
                {item.actor && <span>actor {item.actor}</span>}
                {item.source_ip && <span>from {item.source_ip}</span>}
                {item.hostname && <span>on {item.hostname}</span>}
                {item.outcome && <span>outcome {item.outcome}</span>}
              </div>
            </div>
          </li>
        ))}
      </ol>

      {hover && (
        <div className="tooltip" style={{ left: hover.x + 12, top: hover.y + 12 }}>
          <strong>{hover.item.title}</strong>
          <div className="tooltip-row">
            <span className="muted">time</span>
            <span>{dateTime(hover.item.time)}</span>
          </div>
          <div className="tooltip-row">
            <span className="muted">kind</span>
            <span>{kindLabel(hover.item)}</span>
          </div>
          {hover.item.tactics.length > 0 && (
            <div className="tooltip-row">
              <span className="muted">tactics</span>
              <span>{hover.item.tactics.join(", ")}</span>
            </div>
          )}
          {hover.item.event_id && (
            <div className="tooltip-row">
              <span className="muted">event</span>
              <span className="mono">{hover.item.event_id.slice(0, 8)}</span>
            </div>
          )}
        </div>
      )}
    </>
  );
}
