terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Configure a remote backend before using this for anything shared.
  # backend "s3" {
  #   bucket         = "signalforge-tfstate"
  #   key            = "signalforge/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "signalforge-tflock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}

locals {
  name = "${var.project}-${var.environment}"

  tags = merge(
    {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "detection-and-response"
    },
    var.tags,
  )

  # Settings shared by every task definition. Secrets are injected separately
  # from Secrets Manager, never as plain environment values.
  common_environment = {
    SIGNALFORGE_ENVIRONMENT              = var.environment
    SIGNALFORGE_BUS_BACKEND              = "kafka"
    SIGNALFORGE_EVENT_STORE_BACKEND      = "opensearch"
    SIGNALFORGE_DETECTIONS_PATH          = "/app/detections"
    SIGNALFORGE_RESPONSE_DRY_RUN         = "true"
    SIGNALFORGE_RESPONSE_REQUIRE_APPROVAL = "true"
    SIGNALFORGE_OTEL_ENABLED             = "true"
    SIGNALFORGE_LOG_LEVEL                = "INFO"
  }
}

resource "random_password" "jwt_secret" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "jwt" {
  name                    = "${local.name}/jwt-secret"
  description             = "Signing key for SignalForge access and refresh tokens."
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id     = aws_secretsmanager_secret.jwt.id
  secret_string = random_password.jwt_secret.result
}

resource "aws_cloudwatch_log_group" "services" {
  name              = "/${local.name}/services"
  retention_in_days = var.log_retention_days
}

resource "aws_sns_topic" "alarms" {
  name = "${local.name}-platform-alarms"
}

resource "aws_sns_topic_subscription" "alarms_email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# NOTE: network.tf, data.tf and ecs.tf are the remaining pieces of this module.
# They are intentionally not stubbed with half-configured resources - an
# incomplete `aws_ecs_service` that looks applyable is worse than an honest gap.
# See README.md in this directory for the target topology and the roadmap entry
# for status.
