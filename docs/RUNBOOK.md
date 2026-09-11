# Runbook

Operating SignalForge: what to check, in what order, when something looks wrong.

## Health checks

| Endpoint | Meaning |
|---|---|
| `GET /api/v1/health/live` | The process is up. Use for liveness probes. |
| `GET /api/v1/health/ready` | Rules loaded cleanly *and* the event store answers. Use for readiness. |
| `GET /api/v1/health` | Backends in use, rule counts, load errors, uptime. |
| `GET /api/v1/pipeline/stats` | Engine counters: processed, deduped, suppressed, windows open. |
| `GET /metrics` | Prometheus exposition (also per worker, on `metrics_port + n`). |

`ready` returns `degraded` — not an error — when a rule failed to load, and
names the file. That is deliberate: one bad rule should not take detection down,
but it must be visible.

## "No alerts are firing"

Work down the pipeline; each step tells you whether to stop there.

1. **Are events arriving?**
   `rate(signalforge_events_ingested_total[5m])` — if zero, the problem is
   collection, not detection. Check the collector/Vector logs and, in file mode,
   that `SIGNALFORGE_COLLECTOR_FILES` paths exist and are readable.
2. **Are they being normalized?**
   `rate(signalforge_events_normalized_total[5m])` and
   `signalforge_normalization_failures_total`. A spike in failures with a stable
   `source` label means that vendor changed its log shape — read the DLQ topic,
   then fix the mapper.
3. **Are events reaching the store?**
   `signalforge_events_indexed_total{outcome="indexed"}` and
   `signalforge_spooled_events`. Non-zero spool means the store is unreachable;
   nothing is lost, but nothing is searchable either.
4. **Are rules loaded?**
   `signalforge_rules_loaded` and `GET /api/v1/detections/lint`.
5. **Are rules matching?**
   `GET /api/v1/pipeline/stats` → `rules_evaluated` climbing but `matches` flat
   means the events do not look the way the rules expect. Pull an event
   (`POST /api/v1/events/search`) and compare it field by field to the rule.
   Retro-hunt the rule to check the same thing server-side.
6. **Are alerts being suppressed?**
   `alerts_suppressed` and `alerts_deduped` in the same stats blob. Suppression
   is usually the asset inventory doing its job — check whether the principal is
   in `service_accounts` or `load_test_accounts`.

## "Too many alerts"

- `GET /api/v1/stats/overview` → `top_rules` ranks by occurrences: that is the
  tuning worklist.
- For the offending rule, read a few alerts' `matched_fields` — the reason is
  always there.
- Fix it in the rule (a `filter_*` search) or in the inventory (if a whole class
  of accounts is expected to look odd), then add the case to the rule's tests as
  a `false_positive`.
- Short term, raise `signalforge.suppress` on the rule so one entity fires at
  most once per window.

## "Consumer lag is growing"

```
signalforge_consumer_lag{group="signalforge.detector"} > 10000
```

1. Which stage? The lag metric is labelled by group, so the slow hop is named.
2. Detector lag: check `signalforge_detection_latency_seconds` p95. Common
   causes are a very broad rule (no `logsource`, so it is evaluated against
   everything) or a huge sliding window.
3. Normalizer lag: usually the event store. Check `INDEX_LATENCY` and the
   OpenSearch cluster's own health.
4. Scale the affected service (`docker compose up -d --scale normalizer=4`).
   **Note:** scaling the *detector* without bus partitioning splits window
   state; see the roadmap. Normalizer and enricher scale freely.

## "Events are spooled"

```
signalforge_spooled_events > 0
```

The event store rejected writes and events are on disk at
`var/spool/events.ndjson`. They are not lost.

1. Fix the store (usually disk, heap or a red cluster status).
2. The worker's `flush_spool` task retries every minute; force it with
   `celery -A services.worker.tasks call signalforge.flush_spool`.
3. Confirm `signalforge_spooled_events` returns to zero.

If the spool file grows unbounded, the cluster has been down long enough that
you should decide whether to keep buffering or drop — that is a judgement call
the platform deliberately does not make for you.

## "An incident looks wrong"

- **Too high a score?** `GET /api/v1/incidents/<key>` returns `risk_factors`,
  which lists every contributing factor and multiplier. The model is documented
  in the README; nothing about a score is hidden.
- **Wrong entity?** Check identity resolution: `schemas/identities.yml` maps
  aliases to canonical emails. An unmapped alias means the stages will not group.
- **Missing stages?** The correlation's `timespan` may be shorter than the real
  activity, or one stage's rule did not fire (check the alert queue filtered by
  that `rule_id`).
- **Duplicate incidents?** Two incidents with the same title and entity mean the
  dedup key differed — most often because one alert had no principal, so the
  group key changed.

## Running a response action

1. An analyst requests a playbook from the incident page (or
   `POST /api/v1/response/incidents/<key>/actions`).
2. It sits in `pending_approval`. **Nothing has happened yet.**
3. A responder or admin — not the requester — approves it. With
   `SIGNALFORGE_RESPONSE_DRY_RUN=true` (the default) the action reports what it
   *would* do and changes nothing.
4. Check the result on the incident timeline and in
   `GET /api/v1/incidents/<key>/audit`.

To let playbooks actually act on the lab resources, set
`SIGNALFORGE_RESPONSE_DRY_RUN=false`. Do this only where you own the targets.
`SIGNALFORGE_RESPONSE_REQUIRE_APPROVAL=false` exists for automated tests; it
logs a warning on every use and should never be set in a deployment people rely
on.

## Rule deployment

```bash
python scripts/validate_rules.py detections     # before anything else
pytest tests/detections -q
curl -X POST localhost:8000/api/v1/detections/reload -H "authorization: Bearer $TOKEN"
```

`reload` re-reads the directory, re-indexes the rule set and bumps the registry
revision for anything whose content hash changed — no restart required. If a
rule fails to parse, the reload response lists it and the previous rule set stays
in place for the rules that still load.

## Backup and restore

- **PostgreSQL** holds everything an analyst produced (incidents, notes, audit,
  approvals). Back it up. `pg_dump signalforge` is enough at this scale.
- **OpenSearch** holds the events. It is reconstructible from the source logs if
  you keep them, so snapshot policy is a cost decision.
- **`detections/` and `schemas/`** are in git — that *is* the backup, and it is
  why detection-as-code matters operationally.

## Upgrades

The metadata schema is created with `Base.metadata.create_all` on start, which
adds new tables but does not alter existing ones. There is no migration tool
wired in yet (Alembic is the obvious choice); for now, a breaking model change
needs a manual migration or a rebuild of the metadata database. The event store
has no such constraint — its mapping is dynamic and keyword-by-default.
