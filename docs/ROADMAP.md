# SignalForge roadmap

Status legend: **done** · **partial** — works but has a named gap · **planned**.

Everything marked *done* has code and tests in this repository. Nothing here is
aspirational unless it says *planned*.

---

## Phase 1 — one complete flow (done)

The rule was: do not start with twenty log sources. Get a single Linux
authentication event all the way through, then widen.

| Deliverable | Status | Notes |
|---|---|---|
| OCSF-shaped event model | **done** | `signalforge.models.ocsf` — classes, activities, status/severity, observables, enrichments, content-hash dedup key |
| Linux `sshd` mapper | **done** | Also `sudo`, shadow-utils and auditd |
| Event bus abstraction | **done** | Kafka/Redpanda + in-process, at-least-once, manual commits, DLQ |
| Security event store | **done** | OpenSearch + in-memory, idempotent writes, retry/backoff, on-disk spool |
| Sigma engine | **done** | Condition parser, field modifiers, streaming evaluator, OpenSearch DSL backend |
| First detection with tests | **done** | `sf-auth-0001` repeated authentication failures |
| Alert → incident → timeline | **done** | Incident state machine, dedup, entity-pivot timeline |
| Dashboard | **done** | Next.js overview, incidents, alerts, detections, supply chain, lab |

## Phase 2 — widen the sources (done)

| Deliverable | Status | Notes |
|---|---|---|
| AWS CloudTrail mapper | **done** | Console login, IAM, S3/datastore, trail tampering, SAML detection |
| Okta System Log mapper | **done** | Sessions, privilege grants, MFA factors, API tokens, geo/proxy context |
| Application audit mapper | **done** | Logins, role changes, tokens, data access, HTTP activity |
| Identity resolution | **done** | `schemas/identities.yml`; one human across `sshd`, app and cloud |
| Asset criticality inventory | **done** | `schemas/assets.yml`, glob patterns, service/load-test accounts |

## Phase 3 — detection engineering (done)

| Deliverable | Status | Notes |
|---|---|---|
| 11 shipped rules across 6 domains | **done** | authentication, identity, credentials, cloud, endpoint, application |
| 3 Sigma v2 correlation rules | **done** | brute-force→success, impossible travel, account compromise |
| Positive / negative / false-positive tests per rule | **done** | 60+ declarative cases, run by `tests/detections` |
| Rule linter as a CI gate | **done** | `scripts/validate_rules.py`, including OCSF field-name validation |
| Rule versioning | **done** | Content-hash revisions in the `detections` registry, exposed via the API |
| Retro-hunting | **done** | Rule → OpenSearch DSL, plus an in-memory DSL interpreter for laptops |
| pySigma cross-validation | **planned** | Parse the shipped rules with pySigma in CI as a second opinion |
| Import upstream SigmaHQ rules | **planned** | The field-mapping pipeline exists; needs a curation and triage workflow |

## Phase 4 — correlation, risk, ATT&CK (done)

| Deliverable | Status | Notes |
|---|---|---|
| Four correlation types | **done** | `event_count`, `value_count`, `temporal`, `temporal_ordered` |
| Sliding-window state | **partial** | In-process per replica; see *shared window state* below |
| Risk model | **done** | Documented experimental model, exposed bands, reproducible worked example |
| ATT&CK mapping | **done** | Tactics ordered by kill chain, techniques linked out |
| Behavioural context signals | **done** | 11 documented modifiers, including suppressing ones |
| Baseline / anomaly signals | **planned** | "First seen for this user" is stubbed as a context signal but not computed from history |

## Phase 5 — enrichment, response, testing (done)

| Deliverable | Status | Notes |
|---|---|---|
| Multi-provider threat intel | **done** | Internal, static feed, optional HTTP; merge by verdict rank |
| Caching + retry + circuit breaker | **done** | Redis or in-process; degraded verdict instead of an exception |
| Approval-gated playbooks | **done** | Eight playbooks, four-eyes approval, dry-run default, audited |
| Failure-mode tests | **done** | Duplicates, out-of-order, crash-resume, store outage, tenancy, 10k burst |
| Response integration adapters | **planned** | Real IdP/cloud adapters, deliberately out of scope until there is a consent model |

## Phase 6 — containers, CI/CD, monitoring, load (done / partial)

| Deliverable | Status | Notes |
|---|---|---|
| Docker Compose stack | **done** | Redpanda, OpenSearch, PostgreSQL, Redis, API, dashboard, 6 services, profiles |
| Multi-stage images | **done** | Non-root, health checks, dependency-first layers |
| GitHub Actions CI | **done** | Detection lint + tests, Python matrix, dashboard build, backend integration, image builds |
| Prometheus + Grafana | **done** | Per-service metrics, pipeline dashboard, platform alert rules |
| OpenTelemetry tracing | **partial** | Wiring and exporter config are in place; spans are not yet threaded through the pipeline hops |
| Load harness | **done** | Generator, rate control, throughput/latency/loss measurement |
| Single-process benchmark | **done** | 3,603 events/sec end to end, p95 detection latency 0.42 ms, zero loss over 20k events (M4 Pro, in-process backends) - see the README |
| **Distributed benchmark** | **planned** | The published figure is single-process. The same measurement through Redpanda + OpenSearch + PostgreSQL is the number that would justify a "scales to X" claim |
| Terraform deployment | **partial** | Skeleton module in `infrastructure/terraform`; not applied against a real account |

---

## Phase 7 — multi-analyst operations (in progress)

SignalForge started as a single-analyst tool: an incident had one free-text
`owner`, and anyone with the `analyst` role could move it through the state
machine. A real SOC runs on **queues, shifts and handovers** — an incident is
opened by a detection, routed to a team, claimed by a person, escalated to
another team when it turns out to be something else, and closed by someone
accountable.

The queue mechanics and the permission model are now in place (see *Delivered
so far*), built on what was already there: the state machine, the audit trail
and the tenancy model. What remains is routing rules, SLA timers and the
dashboard surface for all of it.

### Delivered so far

| Piece | State |
|---|---|
| Alembic migrations | **done** - baseline + the Phase 7 delta, with tests asserting the chain matches the models, preserves rows on upgrade and rolls back cleanly |
| Teams and membership | **done** - `TeamService`, per-tenant slugs, one default queue, `lead`/`member` roles, audited |
| Queue ownership | **done** - route, claim, unclaim, transfer-with-a-reason; claiming someone else's incident is a `409` |
| `WAITING` state | **done** - requires a wake-up time and a reason; `due_for_wake_up()` gives the worker its input |
| Per-transition permissions | **done** - containment needs a responder; closing as a false positive needs admin **or** a lead of the owning team |
| Optimistic concurrency | **done** - `version` column; a stale write is a `409` rather than a silent overwrite |
| Queue and handover views | **done** - `/teams/{slug}/queue` (oldest first) and `/teams/{slug}/handover` |
| Verified on PostgreSQL | **done** - the CI integration job applies the migration and runs the suite against real PostgreSQL, not just SQLite batch mode |
| Routing rules | **planned** - queues are populated by transfer today; `routing/*.yml` is the next piece |
| SLA timers and SOC metrics | **planned** - `acknowledged_at` is recorded, so MTTA is already derivable |
| Presence, comments, mentions | **planned** |
| Dashboard queue UI | **planned** - the API is in place; the analyst UI still shows the risk-ranked list only |

### What is left

**1. Routing rules.** Queues are populated by an explicit transfer today, which
means a new incident sits unrouted until somebody moves it — the most obvious
remaining gap. `routing_rules` (tenant, priority, match, team): match on
scenario, correlation id, severity, ATT&CK tactic, asset criticality or source,
first match wins, with the default queue as the fallback. Routing belongs in git
for the same reasons detections do, so these should live in `routing/` as YAML
and be linted by the same CI gate.

**2. SLAs and the metrics that come with them.** Per-severity targets for
time-to-acknowledge and time-to-resolve, stored as `sla_ack_due` /
`sla_resolve_due` when the incident opens, with a worker flagging breaches and
escalating. `acknowledged_at` is already recorded on first claim, so MTTA is
derivable now; the rest is the reporting layer:

| Metric | Definition | Status |
|---|---|---|
| MTTD | detection time − first event time | derivable from the timeline |
| MTTA | `acknowledged_at` − `created_at` | **data present**, no reporting yet |
| MTTR | `closed_at` − `created_at`, by disposition | **data present**, no reporting yet |
| Queue age | oldest unclaimed incident per queue | `/teams/{slug}/queue` is oldest-first, not aggregated |
| Reopen rate | incidents leaving a terminal state, per closer | in the audit trail, not aggregated |

**3. The dashboard queue UI.** The whole of Phase 7 is API-only. There is no
queue switcher (**My work · My team · Unassigned · All**), no claim button, no
assignee or SLA chips, no handover page. For anyone looking at the dashboard
rather than the OpenAPI spec, the feature does not visibly exist — which makes
this the highest-value remaining item even though it is not the deepest.

**4. Presence and collision warnings.** Optimistic concurrency already stops a
stale write, but it tells the analyst *after* they have typed. A short-lived
presence key (Redis, ~30s TTL) driving "Dana is viewing this" prevents the
collision rather than reporting it.

**5. Collaboration surface.** Threaded comments with `@mention` (notify, and add
the mentioned user as a watcher), explicit watchers independent of assignment,
and case **linking and merging** — two incidents that turn out to be one
intrusion should become one case with both evidence sets, which the supersession
mechanism already models for the automated path.

**6. Notifications.** A pluggable channel interface (webhook, Slack, PagerDuty,
email) driven off the audit stream, firing on assignment, mention, SLA breach
and escalation. The audit log is already the event source, so this is a
consumer, not a new pipeline.

### API surface

Shipped:

```
GET    /teams                          POST /teams
GET    /teams/mine                     DELETE /teams/{slug}
POST   /teams/{slug}/members           DELETE /teams/{slug}/members/{user}
POST   /teams/{slug}/default
GET    /teams/{slug}/queue             # oldest-unclaimed-first
GET    /teams/{slug}/handover          # the shift handover projection
POST   /incidents/{ref}/claim          POST /incidents/{ref}/unclaim
POST   /incidents/{ref}/transfer       { team, reason }
GET    /incidents?mine=true&team=&unclaimed=&order=oldest
```

Still to come:

```
POST   /incidents/{ref}/watch          DELETE /incidents/{ref}/watch
GET    /incidents/{ref}/comments       POST /incidents/{ref}/comments
POST   /incidents/{ref}/link           { incident, relationship }
GET    /stats/soc                      # MTTA/MTTR/queue age by team and analyst
```

### Sizing, honestly

The queue mechanics took roughly a day, most of it schema, service methods and
tests — helped by the audit trail and state machine already being there. The
dashboard queue UI is a similar size and is what makes any of it visible.
Routing rules are smaller than they look because the rule-loading and linting
machinery already exists and can be pointed at a second directory. SLAs are
mostly reporting. Presence, comments and notifications are independent and can
land in any order.

---

## Named gaps, in the order I would fix them

1. **Benchmark the distributed path.** The published figure (3,603 events/sec,
   p95 0.42 ms, zero loss) is a single-process measurement with the in-process
   bus and event store — it proves the engine is not the bottleneck, nothing
   more. Run the same workload through the compose stack (Redpanda, OpenSearch,
   PostgreSQL) with the collector feeding it, and record where it actually
   saturates: bulk-index latency, consumer lag, or rule evaluation.
2. **Shared window state for detection and correlation.** Sliding windows are
   in-process, so two detector replicas each see part of a burst and a
   `count() by user >= 5` rule can miss a threshold that is only crossed
   across both. Two options: partition the bus by principal so one replica owns
   an entity (cheap, keeps the fast path in memory), or move windows to Redis
   sorted sets (slower, but replica-count-independent). Partitioning first.
3. **httpOnly cookie auth for the dashboard.** The token currently lives in
   `sessionStorage`, which is XSS-reachable. Move to an httpOnly, `SameSite=Strict`
   cookie issued by a Next.js route handler, with a CSRF token on mutations.
4. **API rate limiting and request quotas.** There is no protection against a
   client hammering `/events/ingest` or `/detections/retro-hunt`; a Redis token
   bucket per tenant and per route is the obvious fix.
5. **Trace the pipeline hops.** OTLP export is configured but spans are not
   propagated across the bus, so a slow event cannot be followed
   collector → normalizer → detector → correlator. Inject trace context into
   the record envelope and continue the span in each service.
6. **pySigma as a second parser in CI.** The Sigma implementation here is my
   own; running the shipped rules through pySigma as well would catch any place
   where my semantics drift from the reference implementation.
7. **Baseline-driven context.** `first_seen_source` is a declared context signal
   with no history behind it. Computing per-principal baselines (usual hours,
   usual countries, usual resources) from the event store would make
   "unusual for *this* account" a real signal rather than a static rule.
8. **Alert tuning workflow.** The dashboard shows the noisiest rules; the next
   step is closing the loop — mark an alert a false positive, and have that
   produce a proposed rule filter as a pull request.
9. **Retention and lifecycle.** OpenSearch ISM policies for tiering and
   deletion, plus an incident archive, so a long-running deployment does not
   grow without bound.
10. **Kubernetes manifests / Helm chart.** Compose is the supported path today;
    a chart with an HPA on consumer lag is the natural next deployment target.
11. ~~**Schema migrations (Alembic).**~~ **Done.** `alembic upgrade head` runs
    on startup (`db_auto_migrate`), the test suite still builds throwaway
    databases from the models for speed, and `tests/integration/test_migrations.py`
    is what stops the two drifting apart.
12. **Multi-analyst operations** — Phase 7 above. The queue mechanics, the
    permission model and the migration groundwork are in; routing rules, SLA
    timers and the dashboard queue UI are what remain.

## Future scope, by theme

Beyond the ordered gaps, the directions worth pursuing:

**Detection engineering.** Import and curate upstream SigmaHQ rules (the field
pipeline already exists; the missing part is a triage workflow for 3,000 rules).
Shadow mode — run a new rule for a week recording volume and matched entities
*without* alerting, so tuning happens before anyone is paged. Coverage gap
reporting against the ATT&CK matrix, driven off the existing `/stats/mitre`.
A false-positive feedback loop that turns "close as FP" into a proposed rule
filter as a pull request.

**Data platform.** Replay tooling: re-run a day of raw records through a fixed
mapper — the bus plus content-hash dedup already make this safe, it just needs
a command. Event schema versioning for when the OCSF subset changes.
OpenSearch ISM for tiering and retention.

**Intelligence.** Per-principal baselines (usual hours, countries, resources) to
make "unusual for *this* account" a computed signal rather than a static rule.
MISP/STIX ingestion alongside the static feed, with indicator confidence decay
so stale intel stops inflating scores.

**Response.** Real adapters (IdP, cloud) behind an explicit consent and
blast-radius model. Playbook dry-run diffs — show exactly what *would* change
before approval. Rollback for every containment action.

**Security hardening.** httpOnly cookie auth and rate limiting (gaps 3 and 4),
SSO/OIDC with SCIM provisioning, per-team RBAC, and a tamper-evident audit log
(hash-chained entries) — an audit trail that can be edited by whoever owns the
database is weak evidence.

**Reporting.** Incident report export (PDF/Markdown) for a finished
investigation, scheduled executive digests, and per-team performance reporting
off the Phase 7 metrics.

## Explicitly out of scope

- **Offensive tooling.** No exploitation, no credential attacks, no evasion.
  The scenario generators emit *logs*, never traffic against a target.
- **Response adapters for third-party systems** (real IdP, real cloud accounts).
  The playbook framework is deliberately limited to resources this deployment
  owns until there is a consent and blast-radius model worth trusting.
- **Scraped or unlicensed threat-intel sources.** The bundled feed is
  checked-in, documented test data; live enrichment is opt-in and points at a
  provider the operator is authorised to query.
