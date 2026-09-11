output "name_prefix" {
  description = "Resource name prefix used by this deployment."
  value       = local.name
}

output "jwt_secret_arn" {
  description = "Secrets Manager ARN of the token signing key."
  value       = aws_secretsmanager_secret.jwt.arn
}

output "log_group" {
  description = "CloudWatch log group every service writes to."
  value       = aws_cloudwatch_log_group.services.name
}

output "alarm_topic_arn" {
  description = "SNS topic that platform-health alarms publish to."
  value       = aws_sns_topic.alarms.arn
}

# Populated once network.tf / data.tf / ecs.tf land:
# output "api_url"            { value = aws_lb.public.dns_name }
# output "opensearch_endpoint" { value = aws_opensearch_domain.events.endpoint }
# output "postgres_endpoint"   { value = aws_db_instance.metadata.address }
# output "kafka_bootstrap"     { value = aws_msk_cluster.bus.bootstrap_brokers_tls }
