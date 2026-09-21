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

The queue mechanics, the permission model, automatic routing, service-level
clocks, the SOC metrics and the analyst UI are all in place (see *Delivered so
far*), built on what was already there: the state machine, the audit trail and
the tenancy model. What remains is presence, case linking/merging, and
notification channels.

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
| Routing rules | **done** - `routing/*.yml` in git, priority-ordered with first-match-wins, 11 matchable fields, audited per decision, linted by the same CI gate as detections, plus a preview endpoint that returns every rule's verdict |
| SLA timers | **done** - per-severity acknowledge/resolve clocks from `schemas/sla.yml`, derived breach state, once-only worker escalation, `GET /stats/sla-breaches`, countdown column on the queue |
| SOC metrics | **done** - MTTD/MTTA/MTTR (split by disposition), SLA attainment, queue age and reopen rate per team and analyst; `GET /stats/soc` and a panel on the overview |
| Threaded comments and mentions | **done** - replies nest under their parent, `@handle` resolves on local part or full address, ambiguity reported rather than guessed, unresolved handles returned to the author |
| Watchers | **done** - separate from assignment, records why each person is watching, mention-driven watch never implies ownership |
| Presence | **planned** - optimistic concurrency reports a collision; presence would prevent it |
| Dashboard queue UI | **done** - `/queues` with team depth, scope switcher (My work / Unclaimed / All open), oldest-first ordering and per-row claim; claim/release, park-with-timer and transfer-with-reason on the incident page; the shift-handover report |
| Concurrent-edit UX | **done** - a stale write surfaces the conflict and reloads the page rather than failing silently |

### What is left

**1. Presence and collision warnings.** Optimistic concurrency stops a stale
write and the UI now explains it, but only *after* the analyst has acted. A
short-lived presence key (Redis, ~30s TTL) driving "Dana is viewing this"
prevents the collision rather than reporting it.

**2. Case linking and merging.** Two incidents that turn out to be one intrusion
should become one case with both evidence sets. The supersession mechanism
already models this for the automated path — when a correlation completes, the
stage incidents it absorbed are closed with `Superseded by INC-…` — so the
manual version is mostly an explicit relationship table plus the UI to drive it.

**3. Notifications.** A pluggable channel interface (webhook, Slack, PagerDuty,
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
GET    /routing                        # the table, in evaluation order
POST   /routing/preview                # where would this land, and why
GET    /stats/soc                      # MTTD/MTTA/MTTR, SLA attainment, queue age
GET    /stats/sla-breaches             # open incidents past a deadline
GET    /incidents/{ref}/comments       POST /incidents/{ref}/comments
GET    /incidents/{ref}/watchers       POST/DELETE /incidents/{ref}/watch
```

Still to come:

```
GET    /incidents/{ref}/presence       # who else is looking at this
POST   /incidents/{ref}/link           { incident, relationship }
```

### Sizing, honestly

The queue mechanics took roughly a day, most of it schema, service methods and
tests — helped by the audit trail and state machine already being there. The UI
took about half that, and was where the interesting bug turned up: the page set
an error message and then reloaded, and the reload cleared it, so a `409` was
invisible. Typecheck, lint and build all passed; only driving two browsers at
one incident found it.

Routing took an afternoon, and two of its bugs were only findable by running
it: `rule_id` matching silently never fired during automatic routing (the
incident carries `alert_ids`, not the alert objects the detection ids live on),
and the first shipped table leaned on `scenario`, which only exists for
correlated incidents — so single-alert incidents fell to the catch-all. The
preview endpoint diagnosed the second one, which is a fair argument for having
built it.

SLAs took an afternoon and turned up two things worth recording. Breach state
is derived rather than stored, because a stored flag is wrong the moment a
deadline passes with nothing running — and a *finished* clock has to be judged
on when it finished, or an incident acknowledged inside its window becomes a
breach once the window elapses. The second was the reopen-rate denominator:
dividing by what is closed *now* means a reopened incident vanishes from it
exactly when the metric matters, so it divides by analyst close actions from the
audit trail instead.

Comments took less than expected because notes already existed to extend;
the interesting part was the mention parser, where the word-boundary case (a
bare address in prose reading as a handle) only showed up because a test
asserted the *reason* nothing resolved rather than just the outcome.

Presence and notifications are independent and can land in any order.

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
12. **Make mypy a real gate.** The CI type-check step is
    `continue-on-error: true` and there is a standing backlog of ~90 findings,
    mostly `Optional` handling in the older storage and telemetry modules plus
    missing `types-PyYAML` stubs. An advisory type checker is a type checker
    nobody reads: install the stubs, fix the genuine `None` paths, and drop the
    `continue-on-error`.
13. **Multi-analyst operations** — Phase 7 above. The queue mechanics, the
    permission model and the migration groundwork are in; routing rules, SLA
    timers and the dashboard queue UI are what remain.

## Future scope, by theme

Beyond the ordered gaps. Each of these is something a real SOC asks for; the
note after each says what already exists to build it on, because an idea with
no foothold in the codebase is just a wish.

### Detection engineering

- **Import and curate upstream SigmaHQ rules.** The field-mapping pipeline
  already exists; the missing part is a triage workflow for 3,000 rules — which
  apply to the sources we actually have, and which need field mappings written.
- **Shadow mode.** Run a new rule for a week recording volume and matched
  entities *without* alerting, so tuning happens before anyone is paged. The
  `is_building_block` flag is the precedent: a rule that matches but does not
  page.
- **Noise circuit breaker.** Give each rule an alert-rate budget and auto-mute
  it when it blows past it, with a notification rather than silence. One
  misconfigured rule should not bury a shift.
- **Detection health monitoring.** A rule that has not fired in 30 days while
  its logsource is flowing is probably broken, not lucky. Cross-referencing
  rule hit counts against per-source event volume turns silent detection
  failure into an alert — the failure mode nobody notices until an incident.
- **Log-source health and coverage SLA.** Per-source expected volume with gap
  detection: "`sshd` stopped reporting 40 minutes ago" is a security event.
  Ingestion metrics per source already exist in Prometheus.
- **ATT&CK Navigator layer export.** Emit the coverage view as a Navigator JSON
  layer so it opens in the official tool; `/stats/mitre` already computes it.
- **False-positive feedback loop.** Turn "close as false positive" into a
  proposed rule filter as a pull request — detection tuning as code review.
- **Alert narrative clustering.** Group hundreds of alerts into a handful of
  behavioural narratives. Correlation already does this for known chains; this
  is the unsupervised version for chains nobody wrote a rule for.

### Data platform and scale

- **Replay tooling.** Re-run a day of raw records through a fixed mapper. The
  bus plus content-hash dedup already make this safe; it needs a command and a
  progress report.
- **Schema registry for the OCSF subset**, with compatibility checks in CI so a
  mapper change that breaks a rule fails the build rather than production.
- **Tiered and searchable cold storage** (OpenSearch ISM), plus an incident
  archive, so a long-running deployment stops growing without bound.
- **Backpressure with priority lanes.** Under load, shed verbose low-value
  telemetry before authentication events. The bus has the DLQ and manual commit
  semantics this needs.
- **Multi-region and data residency.** Pin a tenant's events to a region and
  route queries accordingly — the tenancy model already scopes every query.
- **Ingest cost attribution.** Bytes and events per source and tenant against
  the alerts each source actually produced. "This log source costs X and has
  produced two detections in six months" is the report that decides SIEM
  budgets, and almost nothing exposes it.

### Intelligence and analytics

- **Per-principal baselines.** Usual hours, countries, resources and peer
  group, so "unusual for *this* account" becomes computed rather than a static
  rule. `first_seen_source` is declared as a context signal with no history
  behind it — this is what would fill it in.
- **Entity graph and attack-path analytics.** Build user → host → credential →
  resource edges from normalized events and score lateral paths. It answers the
  question the timeline cannot: *what else did this credential touch?*
- **MISP/STIX ingestion** alongside the static feed, with indicator confidence
  decay so stale intel stops inflating scores.
- **Peer-group anomaly detection.** "This account did something no other member
  of its team has ever done" is a stronger signal than a global threshold, and
  the asset/identity inventories already carry the grouping.

### AI-assisted analysis

Worth doing carefully, and worth being explicit about the guardrails, because
this is the area where security tooling most often overclaims:

- **Drafted incident summaries.** A narrative of what happened from the
  timeline and alerts, with every claim citing the event it came from. The model
  drafts; the analyst owns it. **It never changes state** — no transitions, no
  response actions, no closing.
- **Natural language to query.** Translate "show me failed logins for
  contractors outside business hours" into the OpenSearch DSL, and *show the
  generated query before running it*. The Sigma → DSL compiler already proves
  the target shape is machine-generable.
- **Rule authoring assistant.** Propose a Sigma rule from a described behaviour,
  then immediately run the three test kinds against it — the detection test
  harness makes a generated rule falsifiable rather than plausible.
- **An evaluation harness, first.** A fixed set of incidents with known-good
  summaries, scored for faithfulness (does it invent IOCs?) and for whether the
  suggested next step was the one an analyst took. Any of the above without this
  is a demo, not a feature.

### SOC operations

- **On-call rotation and escalation policies.** Who is paged at 03:00, and what
  happens when they do not acknowledge. Teams and membership are in place.
- **Investigation runbooks as code.** Per-scenario checklists — "for a
  suspected credential compromise, confirm these six things" — versioned and
  linted like detections, rendered as a checklist on the incident.
- **Continuous detection validation.** Run a scenario against production on a
  schedule and assert the detection still fires. The lab generator plus the
  detection test harness are most of this already; it is purple-teaming as a
  cron job, and it catches the regression that ships when a mapper changes.
- **Skills-based routing and workload balance.** Route on expertise rather than
  round-robin, and stop assigning to the analyst with fourteen open cases.
- **Post-incident review artefacts.** A blameless PIR document auto-populated
  from the timeline, the audit trail and the response actions taken.

### Compliance and governance

- **Auditor evidence export.** "Show me every privileged access change last
  quarter, with who approved it" — mapped to SOC 2 / ISO 27001 controls. The
  audit trail has the data; it needs the control mapping and an export.
- **Tamper-evident audit log.** Hash-chained entries, because an audit trail
  editable by whoever owns the database is weak evidence.
- **Chain-of-custody bundles.** A hash-sealed evidence export for one incident,
  suitable for handing to someone outside the team.
- **PII minimisation.** Field-level encryption and pseudonymised user
  identifiers, with re-identification gated on a second approval — the same
  four-eyes pattern the playbooks use.
- **Retention and legal hold per tenant**, including defensible deletion.

### Integrations

- **Bidirectional ticketing sync** (Jira/ServiceNow): an incident and its
  ticket should not drift apart.
- **More sources as mappers**: EDR (CrowdStrike, Defender), Entra ID, Kubernetes
  audit, network flow. Each is a mapper plus a field-mapping entry, which is
  the point of normalizing to OCSF in the first place.
- **Generic webhook ingestion** with a per-source mapping definition, so a new
  source does not need a code change.
- **Chat-native workflow** (Slack/Teams): triage from the channel where the
  team already is, with the audit trail recording that it happened there.

### Security hardening

- **httpOnly cookie auth and rate limiting** (gaps 3 and 4).
- **SSO/OIDC with SCIM provisioning**, so joiners and leavers are not manual.
- **Per-team RBAC** beyond the global role hierarchy.
- **Secret management** via a real KMS rather than environment variables.

### Reporting

- **Incident report export** (PDF/Markdown) for a finished investigation.
- **Scheduled digests** — what changed this week, for people who do not open
  the dashboard.
- **Per-team performance reporting** off the Phase 7 metrics.

## Explicitly out of scope

- **Offensive tooling.** No exploitation, no credential attacks, no evasion.
  The scenario generators emit *logs*, never traffic against a target.
- **Response adapters for third-party systems** (real IdP, real cloud accounts).
  The playbook framework is deliberately limited to resources this deployment
  owns until there is a consent and blast-radius model worth trusting.
- **Scraped or unlicensed threat-intel sources.** The bundled feed is
  checked-in, documented test data; live enrichment is opt-in and points at a
  provider the operator is authorised to query.
