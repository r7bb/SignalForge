# Architecture

## The shape of it

```
                 ┌──────────────┐
 host logs ─────▶│              │
 app logs  ─────▶│  Collector   │──▶ sf.logs.raw ──▶┌──────────────┐
 cloud logs ────▶│  (or Vector) │                   │  Normalizer  │
 IdP logs  ─────▶│              │                   └──────┬───────┘
                 └──────────────┘                          │
                                          ┌────────────────┴──────────────┐
                                          ▼                               ▼
                                  OpenSearch                      sf.events.normalized
                              (security events)                          │
                                          ▲                               ▼
                                          │                        ┌─────────────┐
                                          │                        │  Detector   │
                                          │                        └──────┬──────┘
                                          │                               │
                                          │                          sf.alerts
                                          │                          ┌────┴─────┐
                                          │                          ▼          ▼
                                          │                  ┌────────────┐  ┌──────────┐
                                          └──── timeline ────│ Correlator │  │ Enricher │
                                                             └─────┬──────┘  └────┬─────┘
                                                                   ▼              │
                                                             PostgreSQL ◀─────────┘
                                                        (incidents, alerts, audit)
                                                                   ▲
                                                                   │
                                                       ┌───────────┴──────────┐
                                                       │      FastAPI API     │
                                                       └───────────┬──────────┘
                                                                   ▼
                                                          Next.js dashboard
```

Everything is one importable engine (`libs/signalforge`) plus thin deployables.
The API and the workers run the *same* code: the streaming services own one hop
each, and `signalforge.pipeline.Pipeline` runs the whole chain in-process for
tests, the load harness and the synchronous ingest endpoint. There is only one
implementation of the wiring, so the tested path and the deployed path cannot
drift apart.

## Component responsibilities

| Component | Owns | Does not own |
|---|---|---|
| **Collector** | Getting bytes onto the bus, offset bookkeeping | Parsing (beyond identifying the source) |
| **Normalizer** | Vendor shape → OCSF, identity resolution, writing events | Deciding what is suspicious |
| **Detector** | Rule evaluation, sliding-window aggregation, alert scoring, dedup | Joining alerts together |
| **Correlator** | Multi-alert scenarios, opening/extending incidents | Rule semantics |
| **Enricher** | Indicator lookups and caching | Blocking anything (it is additive) |
| **API** | Tenant-scoped reads, analyst workflow, approvals | Detection logic |
| **Worker** | Housekeeping: spool flush, SBOM rematch, retro-hunts | Anything on the hot path |

## Data model boundary

Two stores, chosen for two different jobs:

- **OpenSearch — security events.** Append-mostly, high volume, queried by
  arbitrary field combinations and time ranges. The document `_id` is the event's
  content hash, which makes writes idempotent for free.
- **PostgreSQL — cases and metadata.** Tenants, analysts, the detection
  registry, alerts, incidents, notes, audit rows, response actions, cached
  indicators and the SBOM graph. These need transactions, uniqueness constraints
  and joins, which is exactly what the event store is bad at.

Alerts exist in both worlds: the queryable columns live in PostgreSQL, and the
full pydantic document (evidence, matched fields, enrichments) is stored beside
them as JSONB, so the API can return the rich object without a second lookup.

## Failure behaviour

The interesting part of a pipeline is what it does when something breaks.

| Failure | Behaviour |
|---|---|
| Consumer dies mid-batch | Offsets are committed only after processing, so the batch replays. Reprocessing is safe because the event content hash deduplicates at both the store and the detection engine. |
| A record cannot be normalized | Dead-lettered with the reason attached (`sf.dlq`), counted in `signalforge_normalization_failures_total`. One bad log line never stops the stream. |
| A batch keeps failing | Retried with backoff up to `max_batch_attempts`, then dead-lettered and committed so the consumer cannot wedge. |
| OpenSearch unavailable | Bulk writes retry with exponential backoff and jitter; if it is still down, events are appended to an on-disk spool and flushed by the worker's `flush_spool` task. `signalforge_spooled_events > 0` alerts. |
| Intel provider slow or down | Retry with backoff, then a circuit breaker; the verdict becomes `degraded` and enrichment continues without it. |
| Duplicate log delivery | Same content hash → idempotent overwrite in the store, skipped by the detector, merged into occurrences at the alert layer. |
| Out-of-order arrival | Windows insert in time order and timelines sort by event time, so a late log lands in the right slot. |
| Detector restart | Window state is lost, so an in-flight aggregation may need to re-accumulate. This is the known trade-off of in-process windows — see the roadmap. |

## Why in-process windows

Sliding windows for `count() by user >= 5` and for temporal correlation are held
in memory by the service that owns them. That keeps the hot path free of a
network round trip per event, which is what makes single-process throughput
reasonable. The cost is stated plainly: with more than one detector replica and
no partitioning, each replica sees part of a burst.

The intended fix (roadmap item 2) is to partition the bus by principal so one
replica owns an entity, keeping the fast path in memory while making the result
replica-count-independent. Redis-backed windows are the fallback if partitioning
proves insufficient.

## Multi-tenancy

Tenancy is enforced at the read boundary, not by trusting the caller:

- every token carries a `tenant` claim, and `tenant_scope` resolves the tenant
  for a request from that claim;
- passing a different `?tenant=` is a `403`, including for admins — an admin is
  an admin *of one tenant*;
- fetching a resource by id that exists in another tenant is a `403` rather than
  a `404`, because "not yours" and "does not exist" are different facts and the
  first is the honest answer;
- the event store filters on `sf_tenant`, and every PostgreSQL query filters on
  `tenant`, with `(tenant, dedup_key)` and `(tenant, key)` uniqueness so two
  tenants can hold the same logical identifiers.

## Extending it

**A new log source** is a mapper: subclass `Mapper`, set `source`, implement
`map()`, decorate with `@register`. Nothing else changes — detections are written
against OCSF, so an existing rule immediately covers the new source if it emits
the same event class. Add the source to the Vector config to collect it.

**A new detection** is a YAML file plus a test file in `detections/`. See
[DETECTIONS.md](DETECTIONS.md).

**A new response playbook** is a `Playbook` entry with a handler in
`signalforge/response/playbooks.py`. It inherits the approval gate, the dry-run
default and the audit trail.

**A new enrichment provider** is a `Provider` subclass appended to
`ThreatIntelService.providers`; caching, retry and the circuit breaker are the
service's job, not the provider's.
