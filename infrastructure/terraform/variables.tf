variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "signalforge"
}

variable "environment" {
  description = "Deployment environment (staging, production)."
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "environment must be one of dev, staging, production."
  }
}

variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "availability_zone_count" {
  description = "How many AZs to spread private subnets across."
  type        = number
  default     = 2
}

# ---------------------------------------------------------------- images -----
variable "api_image" {
  description = "Container image for the API service."
  type        = string
}

variable "worker_image" {
  description = "Container image shared by the streaming services and the Celery worker."
  type        = string
}

variable "dashboard_image" {
  description = "Container image for the Next.js dashboard."
  type        = string
}

# --------------------------------------------------------------- capacity ----
variable "api_desired_count" {
  type        = number
  default     = 2
}

variable "normalizer_desired_count" {
  description = "Normalizers scale freely - they are stateless."
  type        = number
  default     = 2
}

variable "detector_desired_count" {
  description = <<-EOT
    Kept at 1 on purpose. Sliding-window detection state is per replica, so
    running two detectors without partitioning the bus by principal would split
    a burst across them and weaken count-based rules. See the roadmap.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.detector_desired_count == 1
    error_message = "Raise this only after bus partitioning by principal is in place."
  }
}

# --------------------------------------------------------------- opensearch --
variable "opensearch_instance_type" {
  type        = string
  default     = "r7g.large.search"
}

variable "opensearch_instance_count" {
  type        = number
  default     = 2
}

variable "opensearch_volume_gb" {
  type        = number
  default     = 100
}

# --------------------------------------------------------------------- rds ---
variable "postgres_instance_class" {
  type        = string
  default     = "db.t4g.medium"
}

variable "postgres_allocated_storage_gb" {
  type        = number
  default     = 50
}

variable "postgres_multi_az" {
  type        = bool
  default     = false
}

# --------------------------------------------------------------------- msk ---
variable "kafka_instance_type" {
  type        = string
  default     = "kafka.m7g.large"
}

variable "kafka_broker_count" {
  type        = number
  default     = 2
}

# ------------------------------------------------------------------ redis ----
variable "redis_node_type" {
  type        = string
  default     = "cache.t4g.small"
}

# ------------------------------------------------------------------- misc ----
variable "log_retention_days" {
  type        = number
  default     = 30
}

variable "alarm_email" {
  description = "Where platform-health alarms are delivered."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Extra tags merged into every resource."
  type        = map(string)
  default     = {}
}
