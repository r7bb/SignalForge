/** API response shapes (mirrors apps/api/app/schemas.py). */

export type RiskLevel = "informational" | "low" | "medium" | "high" | "critical";

export interface AttackTactic {
  slug: string;
  id: string;
  name: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  url: string;
}

export interface AlertSummary {
  alert_id: string;
  rule_id: string;
  rule_title: string;
  rule_level: string;
  status: string;
  risk_score: number;
  risk_level: RiskLevel;
  principal?: string | null;
  source_ip?: string | null;
  hostname?: string | null;
  occurrences: number;
  is_building_block?: boolean;
  first_seen: string;
  last_seen: string;
  tactics: string[];
  techniques: string[];
  incident_id?: string | null;
}

export interface IncidentSummary {
  incident_id: string;
  key: string;
  title: string;
  status: string;
  severity: RiskLevel;
  owner?: string | null;
  assignee_id?: string | null;
  team_id?: string | null;
  team_slug?: string | null;
  acknowledged_at?: string | null;
  sla_ack_due?: string | null;
  sla_resolve_due?: string | null;
  waiting_until?: string | null;
  waiting_reason?: string | null;
  /** Optimistic-concurrency token: send it back on a mutation. */
  version: number;
  risk_score: number;
  risk_level: RiskLevel;
  scenario?: string | null;
  principal?: string | null;
  source_ips: string[];
  hostnames: string[];
  tactics: AttackTactic[];
  techniques: AttackTechnique[];
  alert_count: number;
  evidence_count: number;
  first_seen: string;
  last_seen: string;
  updated_at: string;
}

export interface TimelineItem {
  time: string;
  kind: "event" | "alert" | "response" | "note" | "status";
  title: string;
  detail?: string | null;
  actor?: string | null;
  source_ip?: string | null;
  hostname?: string | null;
  outcome?: string | null;
  severity?: string | null;
  class_name?: string | null;
  event_id?: string | null;
  alert_id?: string | null;
  tactics: string[];
}

export interface ResponseAction {
  id: string;
  playbook: string;
  target?: string | null;
  status: string;
  dry_run: boolean;
  requested_by: string;
  approved_by?: string | null;
  rejected_reason?: string | null;
  executed_at?: string | null;
  result: { ok?: boolean; message?: string; dry_run?: boolean };
  created_at: string;
}

export interface PlaybookOption {
  name: string;
  title: string;
  description: string;
  target_kind: string;
  approver_roles: string[];
  reversible: boolean;
  suggested_target?: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  summary?: string | null;
  risk_factors: string[];
  alerts: AlertSummary[];
  timeline: TimelineItem[];
  notes: Array<{ id: string; time: string; author: string; body: string }>;
  audit: Array<{
    time: string;
    actor: string;
    action: string;
    detail?: string | null;
    data: Record<string, unknown>;
  }>;
  response_actions: ResponseAction[];
  suggested_playbooks: PlaybookOption[];
}

export interface Overview {
  critical_alerts: number;
  high_alerts: number;
  events_today: number;
  open_incidents: number;
  alerts_total: number;
  incidents_total: number;
  mean_detection_latency_ms: number;
  events_by_class: Record<string, number>;
  events_by_severity: Record<string, number>;
  incidents_by_status: Record<string, number>;
  top_rules: Array<{
    rule_id: string;
    rule_title: string;
    alerts: number;
    occurrences: number;
    max_risk: number;
  }>;
  supply_chain: {
    applications?: number;
    components?: number;
    open_findings?: number;
    by_severity?: Record<string, number>;
    affected_applications?: string[];
  };
  generated_at: string;
}

export interface TacticCoverage {
  tactic: string;
  name: string;
  rules: number;
  techniques: string[];
  technique_count: number;
  incidents: number;
}

export interface RuleSummary {
  id: string;
  name?: string | null;
  title: string;
  kind: "detection" | "correlation";
  level: string;
  status: string;
  description?: string | null;
  author?: string | null;
  logsource: Record<string, string>;
  tactics: string[];
  techniques: string[];
  falsepositives: string[];
  stateful: boolean;
  timeframe_seconds?: number | null;
  condition?: string | null;
  correlation_type?: string | null;
  correlation_rules: string[];
  source_path?: string | null;
  revision?: number | null;
}

export interface LintReport {
  ok: boolean;
  rule_count: number;
  correlation_count: number;
  tested_rules: number;
  errors: Array<{ path: string; code: string; message: string; rule_id?: string }>;
  warnings: Array<{ path: string; code: string; message: string; rule_id?: string }>;
}

export interface SupplyChainApp {
  id: string;
  name: string;
  environment: string;
  criticality: string;
  owner?: string | null;
  components: number;
  sbom_format?: string | null;
  ingested_at?: string | null;
  open_vulnerabilities: number;
}

export interface SupplyChainFinding {
  application: string;
  criticality: string;
  vuln_id: string;
  title?: string | null;
  severity: string;
  cvss_score?: number | null;
  component: string;
  version: string;
  purl: string;
  direct: boolean;
  fixed_version?: string | null;
}

export interface VulnerabilityImpact {
  vuln_id: string;
  known: boolean;
  title?: string | null;
  severity: string;
  cvss_score?: number | null;
  package: string;
  ecosystem?: string | null;
  affected_range: string;
  fixed_version?: string | null;
  references: string[];
  applications: Array<{
    application: string;
    environment: string;
    criticality: string;
    owner?: string | null;
    status: "affected" | "unaffected" | "not_present";
    findings: Array<{
      component: string;
      version: string;
      purl: string;
      direct: boolean;
      affected: boolean;
      fixed_version?: string | null;
    }>;
  }>;
}

export interface Session {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: {
    id: string;
    email: string;
    role: string;
    tenant: string;
    full_name?: string | null;
  };
}

export interface TeamMember {
  user_id: string;
  email: string;
  full_name?: string | null;
  role: "member" | "lead";
}

export interface Team {
  id: string;
  slug: string;
  name: string;
  description?: string | null;
  is_default: boolean;
  open_incidents: number;
  unclaimed_incidents: number;
  members: TeamMember[];
  /** Only present on /teams/mine. */
  is_lead?: boolean;
}

export interface QueueIncident {
  key: string;
  title: string;
  status: string;
  severity: RiskLevel;
  risk_score: number;
  owner?: string | null;
  principal?: string | null;
  first_seen: string;
  acknowledged_at?: string | null;
  waiting_until?: string | null;
  version: number;
  sla?: SlaState | null;
}

export interface SlaClock {
  name: "acknowledge" | "resolve";
  due_at?: string | null;
  completed_at?: string | null;
  state: "ok" | "at_risk" | "breached" | "met" | "none";
  seconds_remaining?: number | null;
  seconds_over?: number | null;
}

export interface SlaState {
  state: SlaClock["state"];
  acknowledge: SlaClock;
  resolve: SlaClock;
  breached: boolean;
}

export interface MetricSummary {
  count: number;
  mean_seconds?: number | null;
  p50_seconds?: number | null;
  p90_seconds?: number | null;
}

export interface SlaAttainment {
  met: number;
  total: number;
  breached: number;
  attainment?: number | null;
}

export interface SocReport {
  window_days: number;
  incidents_opened: number;
  incidents_closed: number;
  mttd: MetricSummary;
  mtta: MetricSummary;
  mttr: { resolved: MetricSummary; false_positive: MetricSummary; combined: MetricSummary };
  sla: { acknowledge: SlaAttainment; resolve: SlaAttainment };
  analyst_closures: number;
  reopened: number;
  reopen_rate?: number | null;
  queues: Array<{
    team: string;
    name?: string | null;
    open: number;
    unclaimed: number;
    oldest_unclaimed_seconds?: number | null;
  }>;
  by_team: Array<{ team: string; name?: string | null; mtta: MetricSummary; mttr: MetricSummary }>;
  by_analyst: Array<{ analyst: string; mtta: MetricSummary; mttr: MetricSummary }>;
}

export interface QueueView {
  team: { slug: string; name: string; id: string };
  incidents: QueueIncident[];
  count: number;
}

export interface HandoverRow {
  key: string;
  title: string;
  status: string;
  risk_score: number;
  owner: string;
  waiting_until?: string | null;
  last_action?: string | null;
  last_actor?: string | null;
  last_action_at?: string | null;
}

export interface HandoverReport {
  team: { slug: string; name: string };
  open_incidents: number;
  unclaimed: number;
  incidents: HandoverRow[];
}

export interface IncidentComment {
  id: string;
  author: string;
  author_id?: string | null;
  body: string;
  mentions: string[];
  parent_id?: string | null;
  created_at: string;
  edited_at?: string | null;
  replies: IncidentComment[];
}

export interface IncidentWatcher {
  user_id: string;
  email: string;
  reason: "mentioned" | "assigned" | "manual";
  since: string;
}

export interface CommentResult {
  threads: IncidentComment[];
  mentioned: string[];
  unresolved_mentions: string[];
  ambiguous_mentions: Record<string, string[]>;
  watchers: IncidentWatcher[];
}
