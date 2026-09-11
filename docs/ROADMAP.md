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

## Explicitly out of scope

- **Offensive tooling.** No exploitation, no credential attacks, no evasion.
  The scenario generators emit *logs*, never traffic against a target.
- **Response adapters for third-party systems** (real IdP, real cloud accounts).
  The playbook framework is deliberately limited to resources this deployment
  owns until there is a consent and blast-radius model worth trusting.
- **Scraped or unlicensed threat-intel sources.** The bundled feed is
  checked-in, documented test data; live enrichment is opt-in and points at a
  provider the operator is authorised to query.
