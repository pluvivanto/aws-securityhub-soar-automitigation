locals {
  slack_enabled = var.slack_bot_token != ""
}

resource "aws_sqs_queue" "slack" {
  count                      = local.slack_enabled ? 1 : 0
  name                       = "sechub-slack-queue"
  visibility_timeout_seconds = 30
  message_retention_seconds  = 3600

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.slack_dlq[0].arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue" "slack_dlq" {
  count                     = local.slack_enabled ? 1 : 0
  name                      = "sechub-slack-dlq"
  message_retention_seconds = 86400
}

resource "aws_sqs_queue_policy" "slack" {
  count     = local.slack_enabled ? 1 : 0
  queue_url = aws_sqs_queue.slack[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.slack[0].arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = module.sns.topic_arn }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "slack" {
  count     = local.slack_enabled ? 1 : 0
  topic_arn = module.sns.topic_arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.slack[0].arn
}

module "slack" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"
  count   = local.slack_enabled ? 1 : 0

  function_name = "sechub-slack"
  description   = "Forwards SNS remediation messages to Slack"
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  timeout       = 30
  memory_size   = 128
  source_path   = "${path.module}/lambda_src/dist/slack"

  environment_variables = {
    SLACK_BOT_TOKEN  = var.slack_bot_token
    SLACK_CHANNEL_ID = var.slack_channel_id
    LOCK_TABLE       = aws_dynamodb_table.patch_lock.name
  }

  cloudwatch_logs_retention_in_days = var.log_retention_days

  attach_policy_json = true
  policy_json = templatefile("${path.module}/policies/slack-handler.json", {
    lock_table_arn = aws_dynamodb_table.patch_lock.arn
    queue_arn      = local.slack_enabled ? aws_sqs_queue.slack[0].arn : ""
  })

  event_source_mapping = {
    sqs = {
      event_source_arn = local.slack_enabled ? aws_sqs_queue.slack[0].arn : null
      batch_size       = 1
    }
  }

  create_current_version_allowed_triggers = false
  depends_on                              = [null_resource.lambda_build]
}
