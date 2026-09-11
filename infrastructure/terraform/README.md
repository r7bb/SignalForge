# Terraform (skeleton)

**Status: not applied against a real account.** This module expresses the target
AWS topology so the shape of a cloud deployment is explicit and reviewable, but
Docker Compose is the supported path today. Treat it as a design artefact until
it has been `terraform apply`-ed and the outputs verified — see the roadmap.

## Target topology

```
                        ┌───────── ALB (HTTPS) ─────────┐
                        ▼                               ▼
                  ECS: dashboard                   ECS: api
                                                        │
        ┌───────────────────────┬───────────────────────┼──────────────┐
        ▼                       ▼                       ▼              ▼
   MSK (Kafka)          OpenSearch domain          RDS PostgreSQL   ElastiCache
        ▲                                                              (Redis)
        │
  ECS: collector · normalizer · detector · correlator · enricher · worker
```

Everything runs in private subnets; only the ALB is public. Services read their
configuration from SSM Parameter Store / Secrets Manager rather than from
environment literals in the task definition.

## Layout

| File | Contents |
|---|---|
| `main.tf` | Providers, locals, tags |
| `variables.tf` | Inputs and their defaults |
| `network.tf` | VPC, subnets, security groups |
| `data.tf` | OpenSearch domain, RDS instance, ElastiCache, MSK cluster |
| `ecs.tf` | Cluster, task definitions, services, autoscaling |
| `outputs.tf` | Endpoints and connection details |

## Usage (once it is real)

```bash
cd infrastructure/terraform
terraform init
terraform plan  -var-file=env/staging.tfvars
terraform apply -var-file=env/staging.tfvars
```

## Deliberate choices

- **Managed services for state.** OpenSearch, RDS and MSK are managed because
  the interesting engineering in this project is the pipeline, not running a
  search cluster.
- **Autoscale on consumer lag, not CPU.** The right signal for a streaming
  service is how far behind it is; `signalforge_consumer_lag` is published for
  exactly this, and normalizer/enricher scale freely. The **detector** does not
  autoscale until bus partitioning lands, because splitting window state across
  replicas would silently weaken count-based detections.
- **No public data plane.** OpenSearch and RDS have no public endpoints; access
  is through the VPC or a bastion/SSM session.
