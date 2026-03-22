# Only created when slack_webhook_url is set

locals {
  slack_enabled = var.slack_webhook_url != ""
}

module "slack" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"
  count   = local.slack_enabled ? 1 : 0

  function_name = "sechub-slack"
  description   = "Forwards SNS remediation messages to Slack"
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  timeout       = 10
  memory_size   = 128
  source_path   = "${path.module}/lambda_src/dist/slack"

  environment_variables = {
    SLACK_WEBHOOK_URL = var.slack_webhook_url
  }

  cloudwatch_logs_retention_in_days = var.log_retention_days

  allowed_triggers = {
    sns = {
      principal  = "sns.amazonaws.com"
      source_arn = module.sns.topic_arn
    }
  }
  create_current_version_allowed_triggers = false
}

resource "aws_sns_topic_subscription" "slack" {
  count     = local.slack_enabled ? 1 : 0
  topic_arn = module.sns.topic_arn
  protocol  = "lambda"
  endpoint  = module.slack[0].lambda_function_arn
}
