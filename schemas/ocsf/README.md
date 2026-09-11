# OCSF subset used by SignalForge

SignalForge normalizes every source into a subset of the
[Open Cybersecurity Schema Framework](https://schema.ocsf.io/) 1.3. The
authoritative definition is the pydantic model in
[`libs/signalforge/signalforge/models/ocsf.py`](../../libs/signalforge/signalforge/models/ocsf.py) —
this file is the human-readable map of what is implemented and why.

## Event classes

| `class_uid` | Class | Category | Emitted by |
|---|---|---|---|
| 1001 | File System Activity | System Activity | auditd |
| 1007 | Process Activity | System Activity | sudo, auditd |
| 3001 | Account Change | IAM | CloudTrail, Okta, app audit |
| 3002 | Authentication | IAM | sshd, CloudTrail, Okta, app audit |
| 3003 | Authorize Session | IAM | sudo |
| 3004 | Entity Management | IAM | Okta |
| 3005 | User Access Management | IAM | CloudTrail, Okta, app audit |
| 3006 | Group Management | IAM | shadow-utils, CloudTrail, Okta |
| 4002 | HTTP Activity | Network Activity | app audit |
| 6001 | Web Resources Activity | Application Activity | app audit |
| 6003 | API Activity | Application Activity | CloudTrail, app audit |
| 6005 | Datastore Activity | Application Activity | CloudTrail (S3), app audit |

`type_uid = class_uid × 100 + activity_id`, as in the specification, and
`category_uid` is derived from the leading digit of `class_uid`.

## Objects

Implemented: `metadata` (with `product`), `actor` (`user`, `session`, `process`,
`authorizations`), `user`, `group`, `src_endpoint` / `dst_endpoint` (with
`location`), `device` (with `os`), `api` (`service`, `request`, `response`),
`http_request` / `http_response`, `resources`, `file`, `observables`,
`enrichments`.

Not implemented (nothing SignalForge reasons about needs them yet): `malware`,
`vulnerabilities` inside events, `cloud`, `container`, `firewall_rule`, `dns`,
`tls`, `email`.

## Enumerations

```
status_id     0 Unknown · 1 Success · 2 Failure · 99 Other
severity_id   0 Unknown · 1 Informational · 2 Low · 3 Medium · 4 High
              5 Critical · 6 Fatal
```

Activity names per class are in `ACTIVITY_NAMES` in the model module; mappers
set only the numeric id and the name is filled in centrally, so a mapper cannot
invent an activity label.

## SignalForge extensions

Anything the platform itself needs lives in its own namespace so an event
remains valid for any other OCSF consumer:

| Field | Purpose |
|---|---|
| `sf_event_id` | Per-ingest identity (a UUID) |
| `sf_tenant` | Tenant that owns the event |
| `sf_source` | Source key that produced it (`linux.sshd`, `aws.cloudtrail`, …) |
| `sf_ingested_at` | When the platform received it |
| `sf_dedup_key` | Content hash — also the event store's document `_id` |
| `sf_raw` | The original line, when there was one |
| `sf_risk_score` | Set when an event contributed to a scored alert |

Two non-standard attributes are carried on standard objects because risk scoring
needs them and OCSF has no equivalent: `device.criticality` and
`resource.criticality`. Both are documented in the model and sourced from
`schemas/assets.yml`.

## Vendor field mapping

`logsource.category` → `class_uid`, and vendor field names → OCSF paths, are
defined in
[`signalforge/sigma/pipeline.py`](../../libs/signalforge/signalforge/sigma/pipeline.py)
(`CATEGORY_TO_CLASS`, `FIELD_ALIASES`). That is what lets a community Sigma rule
written for Windows or CloudTrail field names run against normalized events
without editing it.
