/** Formatting helpers shared by the views. */

import type { RiskLevel } from "./types";

/** 1,284 / 12.9K / 4.2M - compact for stat tiles, exact below 10,000. */
export function compact(value: number): string {
  if (!Number.isFinite(value)) return "-";
  if (Math.abs(value) < 10_000) return value.toLocaleString("en-US");
  if (Math.abs(value) < 1_000_000) return `${(value / 1_000).toFixed(1)}K`;
  if (Math.abs(value) < 1_000_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  return `${(value / 1_000_000_000).toFixed(1)}B`;
}

export function timeOfDay(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function dateTime(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function relative(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime();
  const minutes = Math.round(delta / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function duration(fromIso: string, toIso: string): string {
  const seconds = Math.max(
    0,
    Math.round((new Date(toIso).getTime() - new Date(fromIso).getTime()) / 1000),
  );
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

/** How long ago, in the same units as duration(). Queue age is measured
 *  against now, which is the number that decides what to pick up next. */
export function age(fromIso: string): string {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(fromIso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

/** Risk band -> the reserved status colour (never a series colour). */
export function riskColor(level: RiskLevel | string): string {
  switch (level) {
    case "critical":
      return "var(--status-critical)";
    case "high":
      return "var(--status-serious)";
    case "medium":
      return "var(--status-warning)";
    case "low":
      return "var(--series-1)";
    default:
      return "var(--text-muted)";
  }
}

/** Status colours ship with an icon + label, never colour alone. */
export function riskIcon(level: RiskLevel | string): string {
  switch (level) {
    case "critical":
      return "!!";
    case "high":
      return "!";
    case "medium":
      return "*";
    case "low":
      return "-";
    default:
      return "·";
  }
}

export function riskBand(score: number): RiskLevel {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 50) return "medium";
  if (score >= 30) return "low";
  return "informational";
}

export function statusLabel(status: string): string {
  return status.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

export function titleCase(value: string): string {
  return value.replace(/[_-]/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}
