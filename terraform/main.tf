terraform {
  required_version = ">= 1.5"
  required_providers {
    aws     = { source = "hashicorp/aws", version = ">= 5.0" }
    archive = { source = "hashicorp/archive", version = ">= 2.0" }
    null    = { source = "hashicorp/null", version = ">= 3.0" }
  }

}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
  assume_role {
    role_arn = "arn:aws:iam::${var.account_id}:role/sechub-terraform-deploy"
  }
  default_tags { tags = { Project = "sechub-auto-remediation", ManagedBy = "terraform" } }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.id
  partition   = data.aws_partition.current.partition
  name_prefix = "sechub-remediation"
}

variable "account_id" {
  type        = string
  description = "AWS account ID to deploy into"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_profile" {
  type    = string
  default = ""
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "lambda_timeout" {
  type    = number
  default = 300
}

variable "bedrock_model_id" {
  type    = string
  default = "global.anthropic.claude-opus-4-5-20251101-v1:0"
}

variable "slack_bot_token" {
  type      = string
  default   = ""
  sensitive = true
}

variable "slack_channel_id" {
  type    = string
  default = ""
}

variable "enabled_controls" {
  description = "Control IDs to auto-remediate. [\"*\"] = all."
  type        = list(string)
  default     = ["*"]
}

output "cspm_function_name" { value = module.cspm.lambda_function_name }
output "sns_topic_arn" { value = module.sns.topic_arn }
output "cspm_queue_url" { value = module.sqs_cspm.queue_url }
output "inspector_queue_url" { value = module.sqs_inspector.queue_url }
