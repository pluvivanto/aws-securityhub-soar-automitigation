resource "aws_sqs_queue" "slack" {
  name                       = "sechub-slack-queue"
  visibility_timeout_seconds = 30
  message_retention_seconds  = 3600

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.slack_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue" "slack_dlq" {
  name                      = "sechub-slack-dlq"
  message_retention_seconds = 86400
}

resource "aws_sqs_queue_policy" "slack" {
  queue_url = aws_sqs_queue.slack.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.slack.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = module.sns.topic_arn }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "slack" {
  topic_arn = module.sns.topic_arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.slack.arn
}

module "slack" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"

  function_name = "sechub-slack"
  description   = "Forwards SNS remediation messages to Slack"
  handler       = "handler.handler"
  runtime       = "nodejs24.x"
  timeout       = 30
  memory_size   = 128
  source_path   = "${path.module}/lambda_src/dist/slack"

  environment_variables = {
    SLACK_BOT_TOKEN   = var.slack_bot_token
    SLACK_CHANNEL_ID  = var.slack_channel_id
    SLACK_STATE_TABLE = aws_dynamodb_table.slack_state.name
  }

  cloudwatch_logs_retention_in_days = var.log_retention_days

  attach_policy_json = true
  policy_json = templatefile("${path.module}/policies/slack-handler.json", {
    slack_state_table_arn = aws_dynamodb_table.slack_state.arn
    queue_arn             = aws_sqs_queue.slack.arn
  })

  event_source_mapping = {
    sqs = {
      event_source_arn = aws_sqs_queue.slack.arn
      batch_size       = 1
    }
  }

  create_current_version_allowed_triggers = false
  depends_on                              = [null_resource.lambda_build]
}

module "approval" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"

  function_name = "sechub-approval"
  description   = "Receives Slack approve/reject clicks for new runbook mappings"
  handler       = "handler.handler"
  runtime       = "nodejs24.x"
  timeout       = 10
  memory_size   = 128
  source_path   = "${path.module}/lambda_src/dist/approval"

  environment_variables = {
    SLACK_SIGNING_SECRET = var.slack_signing_secret
    RUNBOOK_CACHE_TABLE  = aws_dynamodb_table.runbook_cache.name
    CSPM_FUNCTION_NAME   = module.cspm.lambda_function_name
  }

  cloudwatch_logs_retention_in_days = var.log_retention_days

  create_lambda_function_url = true
  authorization_type         = "NONE"

  attach_policy_json = true
  policy_json = templatefile("${path.module}/policies/approval-handler.json", {
    runbook_cache_arn = aws_dynamodb_table.runbook_cache.arn
    cspm_function_arn = module.cspm.lambda_function_arn
  })

  create_current_version_allowed_triggers = false
  depends_on                              = [null_resource.lambda_build]
}

resource "aws_lambda_permission" "approval_url" {
  function_name          = module.approval.lambda_function_name
  action                 = "lambda:InvokeFunctionUrl"
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "approval_invoke" {
  function_name            = module.approval.lambda_function_name
  action                   = "lambda:InvokeFunction"
  principal                = "*"
  invoked_via_function_url = true
}

output "slack_interactivity_url" { value = module.approval.lambda_function_url }
