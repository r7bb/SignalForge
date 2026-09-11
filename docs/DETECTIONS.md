# Writing a detection

Detections are code. They live in `detections/<domain>/<name>.yml`, ship with
`<name>.tests.yml`, and are linted and executed in CI.

```
detections/
├── authentication/     logons, brute force, impossible travel
├── identity/           privilege grants, MFA changes
├── credentials/        API keys, tokens, login profiles
├── cloud/              console access, audit-log tampering
├── endpoint/           process and file activity on hosts
├── application/        data access and export
└── correlation/        multi-stage scenarios
```

## 1. Write the rule

```yaml
title: New Access Credential Created      # what an analyst reads first
id: sf-cred-0001                          # stable, never reused
name: credential_created                  # referenced by correlation rules
status: test                              # experimental | test | stable
description: |
  A long-lived credential was created: an IAM access key, an API token or a
  console login profile. Attackers do this immediately after gaining access.
author: SignalForge
date: 2026/04/15
references:
  - https://attack.mitre.org/techniques/T1098/001/
logsource:
  category: iam                           # scopes the rule to OCSF classes
detection:
  selection_account_change:
    class_uid: 3001                       # OCSF Account Change
    activity_id: 1                        # Create
    status: Success
  credential_cloud_key:
    api.operation: [CreateAccessKey, CreateLoginProfile]
  credential_app_token:
    unmapped.action: [api_key_created, service_token_created]
  filter_automation:
    actor.user.type: Service
  condition: selection_account_change and 1 of credential_* and not filter_automation
fields: [actor.user.name, api.operation]  # shown on the alert
falsepositives:                           # be specific; these become tuning work
  - Key rotation performed by a platform engineer or CI pipeline
level: high                               # informational | low | medium | high | critical
tags:
  - attack.persistence
  - attack.t1098.001
signalforge:                              # optional, namespaced extension
  confidence: 8                           # 1-10, feeds the risk model
  dedup_by: [actor.user.name]             # what makes two firings "the same"
  response_playbook: revoke_api_token     # suggested containment
```

**Write against OCSF field paths.** `actor.user.name`, `src_endpoint.ip`,
`api.operation`, `resources.criticality`, `unmapped.<vendor field>`. The linter
rejects a field that is not part of the schema, because a typo is a rule that
silently never fires. Community Sigma field names (`TargetUserName`,
`sourceIPAddress`, `CommandLine`, …) are mapped automatically by the logsource
pipeline, so an upstream rule usually works unchanged.

**Pick `level` for what it means downstream.** It becomes the `severity` factor
of the risk score (`informational` 1 → `critical` 10). A rule that fires
constantly at `high` is worse than useless.

**Set `confidence` honestly.** It is how much you trust *this rule's* logic, not
how bad the behaviour would be. A heuristic with known noise belongs at 5-6.

### Aggregation rules

```yaml
detection:
  selection:
    class_uid: 3002
    activity_id: 1
    status: Failure
  timeframe: 5m                    # required whenever you aggregate
  condition: selection | count() by actor.user.name >= 5
```

Supported: `count()`, `count(<field>)` (distinct), `min`/`max`/`sum`/`avg`,
grouped by any field, compared with `>`/`>=`/`<`/`<=`/`==`/`!=`.

### Correlation rules (Sigma v2)

```yaml
correlation:
  type: temporal_ordered     # event_count | value_count | temporal | temporal_ordered
  rules: [auth_repeated_failures, auth_logon_success, privilege_grant]
  group-by: [actor.user.name]
  timespan: 15m
```

| Type | Fires when |
|---|---|
| `event_count` | N alerts from the referenced rule(s) for one group key |
| `value_count` | N *distinct* values of `condition.field` for one group key |
| `temporal` | Every referenced rule fired inside the window, any order |
| `temporal_ordered` | Every referenced rule fired inside the window, in order |

`group-by` fields resolve against the alert: `actor.user.name` → its principal
(the *canonical* identity, so stages from different sources still group),
`src_endpoint.ip` → its source address, `device.hostname` → its host.

Referencing a rule that does not exist fails the build.

## 2. Write the tests

Three kinds, all mandatory:

```yaml
rule: sf-cred-0001
tests:
  - name: cloud access key creation fires
    kind: positive
    expect: alert
    expect_min_risk: 50
    events:
      - source: aws.cloudtrail
        payload:
          eventName: CreateAccessKey
          userIdentity: {type: IAMUser, userName: alex}
          requestParameters: {userName: alex}
          responseElements: {accessKey: {accessKeyId: AKIAEXAMPLE}}

  - name: token revocation does not fire
    kind: negative
    expect: no_alert
    events:
      - source: app.audit
        payload: {action: api_key_revoked, user: alex@example.com}

  - name: CI pipeline key rotation is filtered
    kind: false_positive
    expect: no_alert
    events:
      - source: aws.cloudtrail
        payload:
          eventName: CreateAccessKey
          userIdentity: {type: IAMUser, userName: ci-deploy}
          requestParameters: {userName: ci-deploy}
```

Event spec keys:

| Key | Meaning |
|---|---|
| `source` | which mapper handles it (`linux.sshd`, `aws.cloudtrail`, `okta.system`, `app.audit`) |
| `raw` | a raw log line; `{time}` becomes a syslog stamp and `{i}` the repeat index |
| `payload` | a structured record; the source's timestamp field is filled in |
| `repeat` / `interval_seconds` | emit it N times, this far apart |
| `at` | start this many seconds after t0 |
| `expect` | `alert` / `no_alert` / `correlation` / `no_correlation` |
| `expect_min_risk` | assert the alert (or incident) scored at least this |

**A false-positive case must pass for a real reason.** Point it at an actual
mechanism: a rule filter, a `Service` account type, or the asset inventory's
`load_test_accounts` (which suppresses via risk context). If your FP case only
passes because nothing matched by accident, it is not testing anything.

## 3. Check it locally

```bash
python scripts/validate_rules.py detections      # metadata, fields, references, tests
pytest tests/detections -q                       # every case, named individually
pytest tests/detections -q -k credential_created # just yours
```

The linter fails on: unparseable YAML, a condition referencing a missing search,
a duplicate id or name, an aggregation without a `timeframe`, a missing ATT&CK
tactic tag, a missing logsource, a field absent from OCSF, an unresolvable
correlation reference, or a missing/incomplete test file. It warns on: no
description, no author, no documented false positives, no technique tag.

## 4. Ship it

```
security/detection-142

Added: sf-cred-0001 New Access Credential Created
Tests: ✓ 3 positive  ✓ 3 negative  ✓ 1 false-positive
Lint:  ✓ 12 detections, 3 correlations, 15 with tests
```

Every edit bumps the rule's revision in the registry (content-hash based), so an
alert can always be attributed to the exact rule version that produced it, and
`GET /api/v1/detections/<id>/versions` shows the history.

## Tuning an existing rule

1. Look at the noisiest rules on the overview page (or
   `GET /api/v1/stats/overview` → `top_rules`).
2. Read the alert's `matched_fields` — that is exactly why it fired.
3. Add a `filter_*` search and reference it in the condition with `and not`.
4. Add the benign case to the rule's tests as a `false_positive` — otherwise the
   next person re-introduces it.
5. If the whole class of activity is expected, prefer the asset inventory
   (`schemas/assets.yml`: `service_accounts`, `load_test_accounts`) over a filter
   in every rule.

## Retro-hunting

New rules should be run over history before they are trusted:

```bash
curl -X POST localhost:8000/api/v1/detections/retro-hunt \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"rule_id":"sf-cred-0001","earliest":"now-30d"}'
```

The rule is compiled to an OpenSearch query (the same AST the live evaluator
uses) and run against stored events; aggregation rules come back grouped.
