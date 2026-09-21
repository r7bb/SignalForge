"use client";

/**
 * Typed API client.
 *
 * The token lives in sessionStorage: it is cleared when the tab closes and is
 * never written to a cookie, so there is nothing for a cross-site request to
 * ride on. A production deployment behind a single origin would move to
 * httpOnly cookies plus CSRF tokens - noted in the roadmap.
 */

import type {
  AlertSummary,
  CommentResult,
  IncidentComment,
  IncidentDetail,
  IncidentSummary,
  IncidentWatcher,
  LintReport,
  Overview,
  PlaybookOption,
  ResponseAction,
  RuleSummary,
  Session,
  HandoverReport,
  QueueView,
  SocReport,
  SupplyChainApp,
  SupplyChainFinding,
  TacticCoverage,
  Team,
  TimelineItem,
  VulnerabilityImpact,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "/api/v1";
const TOKEN_KEY = "signalforge.session";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

export function loadSession(): Session | null {
  if (typeof window === "undefined") return null;
  const raw = window.sessionStorage.getItem(TOKEN_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Session;
  } catch {
    return null;
  }
}

export function saveSession(session: Session): void {
  window.sessionStorage.setItem(TOKEN_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  window.sessionStorage.removeItem(TOKEN_KEY);
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  { auth = true }: { auth?: boolean } = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (auth) {
    const session = loadSession();
    if (session) headers.set("Authorization", `Bearer ${session.access_token}`);
  }

  const response = await fetch(`${BASE}${path}`, { ...init, headers, cache: "no-store" });

  if (response.status === 401 && auth) {
    clearSession();
    throw new ApiError(401, "Session expired - sign in again.");
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      /* keep the status line */
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  body: JSON.stringify(body),
});

export const api = {
  // -- auth ---------------------------------------------------------------
  login: (email: string, password: string, tenant?: string) =>
    request<Session>("/auth/login", json({ email, password, tenant }), { auth: false }),

  me: () => request<{ user_id: string; email: string; tenant: string; role: string }>("/auth/me"),

  // -- overview -----------------------------------------------------------
  overview: () => request<Overview>("/stats/overview"),

  mitre: () => request<{ tactics: TacticCoverage[] }>("/stats/mitre"),

  detectionStats: (hours = 24) =>
    request<{
      window_hours: number;
      alerts: number;
      by_risk_level: Record<string, number>;
      by_rule: Record<string, number>;
      engine: Record<string, number>;
      correlation: Record<string, number>;
    }>(`/stats/detections?hours=${hours}`),

  // -- alerts / incidents -------------------------------------------------
  alerts: (params: Record<string, string | number | undefined> = {}) =>
    request<AlertSummary[]>(`/alerts${query(params)}`),

  alert: (id: string) => request<Record<string, unknown>>(`/alerts/${id}`),

  incidents: (params: Record<string, string | number | boolean | undefined> = {}) =>
    request<IncidentSummary[]>(`/incidents${query(params)}`),

  incident: (reference: string) => request<IncidentDetail>(`/incidents/${reference}`),

  incidentTimeline: (reference: string) =>
    request<{ count: number; entries: TimelineItem[] }>(`/incidents/${reference}/timeline`),

  allowedTransitions: (reference: string) =>
    request<{ status: string; allowed: string[] }>(`/incidents/${reference}/transitions`),

  transition: (
    reference: string,
    status: string,
    reason?: string,
    options: { waitingUntil?: string; expectedVersion?: number } = {},
  ) =>
    request<IncidentSummary>(
      `/incidents/${reference}/status`,
      json({
        status,
        reason,
        waiting_until: options.waitingUntil,
        expected_version: options.expectedVersion,
      }),
    ),

  // -- queue ownership ----------------------------------------------------
  claim: (reference: string, expectedVersion?: number, force = false) =>
    request<IncidentSummary>(
      `/incidents/${reference}/claim`,
      json({ expected_version: expectedVersion, force }),
    ),

  unclaim: (reference: string, reason?: string, expectedVersion?: number) =>
    request<IncidentSummary>(
      `/incidents/${reference}/unclaim`,
      json({ reason, expected_version: expectedVersion }),
    ),

  transfer: (reference: string, team: string, reason: string, expectedVersion?: number) =>
    request<IncidentSummary>(
      `/incidents/${reference}/transfer`,
      json({ team, reason, expected_version: expectedVersion }),
    ),

  // -- teams and queues ---------------------------------------------------
  teams: () => request<{ teams: Team[]; count: number }>("/teams"),

  myTeams: () => request<{ teams: Team[]; count: number }>("/teams/mine"),

  queue: (slug: string, unclaimedOnly = false) =>
    request<QueueView>(`/teams/${slug}/queue${unclaimedOnly ? "?unclaimed_only=true" : ""}`),

  handover: (slug: string) => request<HandoverReport>(`/teams/${slug}/handover`),

  // -- SOC performance ----------------------------------------------------
  socMetrics: (days = 7) => request<SocReport>(`/stats/soc?days=${days}`),

  assign: (reference: string, owner: string | null) =>
    request<IncidentSummary>(`/incidents/${reference}/assign`, json({ owner })),

  addNote: (reference: string, body: string) =>
    request<IncidentDetail>(`/incidents/${reference}/notes`, json({ body })),

  // -- collaboration ------------------------------------------------------
  comments: (reference: string) =>
    request<{ count: number; threads: IncidentComment[] }>(
      `/incidents/${reference}/comments`,
    ),

  addComment: (reference: string, body: string, parentId?: string) =>
    request<CommentResult>(
      `/incidents/${reference}/comments`,
      json({ body, parent_id: parentId }),
    ),

  watchers: (reference: string) =>
    request<{ count: number; watchers: IncidentWatcher[] }>(
      `/incidents/${reference}/watchers`,
    ),

  watch: (reference: string) =>
    request<{ watching: boolean; watchers: IncidentWatcher[] }>(
      `/incidents/${reference}/watch`,
      json({}),
    ),

  unwatch: (reference: string) =>
    request<{ watching: boolean; watchers: IncidentWatcher[] }>(
      `/incidents/${reference}/watch`,
      { method: "DELETE" },
    ),

  // -- response -----------------------------------------------------------
  playbooks: () => request<{ playbooks: PlaybookOption[] }>("/response/playbooks"),

  requestAction: (reference: string, playbook: string, target?: string | null) =>
    request<ResponseAction>(
      `/response/incidents/${reference}/actions`,
      json({ playbook, target }),
    ),

  approveAction: (id: string) =>
    request<ResponseAction>(`/response/actions/${id}/approve`, json({ execute_now: true })),

  rejectAction: (id: string, reason?: string) =>
    request<ResponseAction>(`/response/actions/${id}/reject`, json({ reason })),

  // -- detections ---------------------------------------------------------
  detections: (params: Record<string, string | undefined> = {}) =>
    request<RuleSummary[]>(`/detections${query(params)}`),

  detection: (id: string) => request<Record<string, unknown>>(`/detections/${id}`),

  lint: () => request<LintReport>("/detections/lint"),

  retroHunt: (ruleId: string, earliest = "now-7d") =>
    request<{
      rule_id: string;
      rule_title: string;
      total: number;
      groups: Array<{ key: string; doc_count: number }>;
      events: Array<Record<string, unknown>>;
    }>("/detections/retro-hunt", json({ rule_id: ruleId, earliest })),

  // -- supply chain -------------------------------------------------------
  applications: () => request<{ applications: SupplyChainApp[] }>("/sbom/applications"),

  findings: () => request<{ findings: SupplyChainFinding[] }>("/sbom/findings"),

  impact: (vulnId: string) =>
    request<VulnerabilityImpact>(`/sbom/vulnerabilities/${vulnId}/impact`),

  // -- lab ----------------------------------------------------------------
  scenarios: () =>
    request<{
      scenarios: Array<{
        name: string;
        title: string;
        description: string;
        expected_detections: string[];
      }>;
    }>("/lab/scenarios"),

  simulate: (scenario?: string, normalEvents = 0) =>
    request<{
      scenario: string;
      records: number;
      events: number;
      alerts: number;
      incidents: Array<{ key: string; title: string; risk_score: number }>;
      detections_fired: string[];
      expected_not_fired: string[];
    }>("/lab/simulate", json({ scenario, normal_events: normalEvents })),

  health: () => request<Record<string, unknown>>("/health", {}, { auth: false }),
};

function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "" && value !== false) {
      search.append(key, String(value));
    }
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
}
