# Routing rules

Which queue a new incident lands in. Evaluated in `priority` order (lowest
first); the first matching rule wins; a rule with no `match` block matches
everything and is how the catch-all is written.

**These are example rules keyed to example team slugs** (`identity`,
`cloud-security`, `endpoint`, `soc-triage`). A rule naming a queue the tenant
has not created falls back to the tenant's default queue and logs a warning, so
a slug typo degrades rather than loses the incident — but it is still a bug in
the rule, and `scripts/validate_rules.py` will not catch it because team names
live in the database, not in git.

## Match on `rule_id` first, `scenario` second

`scenario` is only set on incidents a **correlation** rule opened. A severe
single alert opens its own incident with `scenario: null`, so a table built
only on scenarios routes most real traffic to the catch-all.

Detection ids carry the domain, which makes them the reliable signal:

| Prefix | Domain |
|---|---|
| `sf-auth-*` | authentication |
| `sf-idn-*` | identity (roles, MFA, sessions) |
| `sf-cred-*` | credential creation |
| `sf-cloud-*` | cloud control plane |
| `sf-end-*` | endpoint / host |
| `sf-app-*` | application and data access |
| `sf-corr-*` | correlation chains |

Tactic rules sit behind those as a net for detections added later that nobody
has written a routing rule for yet.

## Available match fields

`scenario`, `tactic`, `technique`, `rule_id`, `severity`, `min_risk`,
`max_risk`, `principal`, `hostname`, `source_ip`, `tenant`.

Conditions within one `match` block are ANDed; the values inside a single
condition are ORed. `rule_id`, `technique`, `principal`, `hostname`,
`source_ip` and `scenario` accept glob patterns.

## Checking a change

```bash
python scripts/validate_rules.py detections      # lints routing/ too
curl -X POST localhost:8000/api/v1/routing/preview \
  -H 'content-type: application/json' \
  -d '{"rule_ids": ["sf-idn-0002"], "tactics": ["defense_evasion"]}'
```

The preview returns the winning rule **and every rule with its verdict**, which
is how you see what else a priority change just affected.
