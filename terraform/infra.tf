module "sns" {
  source  = "terraform-aws-modules/sns/aws"
  version = "~> 6.0"
  name    = "${local.name_prefix}-notifications"
}


module "sqs_cspm" {
  source  = "terraform-aws-modules/sqs/aws"
  version = "~> 4.0"

  name                       = "sechub-cspm-queue"
  visibility_timeout_seconds = 360
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 5
  create_dlq                 = true
  dlq_name                   = "sechub-cspm-dlq"
  redrive_policy             = { maxReceiveCount = 3 }
}

module "sqs_inspector" {
  source  = "terraform-aws-modules/sqs/aws"
  version = "~> 4.0"

  name                       = "sechub-inspector-queue"
  visibility_timeout_seconds = 180
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 5
  create_dlq                 = true
  dlq_name                   = "sechub-inspector-dlq"
  redrive_policy             = { maxReceiveCount = 3 }
}

resource "aws_sqs_queue_policy" "cspm" {
  queue_url = module.sqs_cspm.queue_url
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sqs:SendMessage", Resource = module.sqs_cspm.queue_arn }]
  })
}

resource "aws_sqs_queue_policy" "inspector" {
  queue_url = module.sqs_inspector.queue_url
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sqs:SendMessage", Resource = module.sqs_inspector.queue_arn }]
  })
}

resource "aws_dynamodb_table" "patch_lock" {
  name         = "sechub-patch-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "instanceId"

  attribute {
    name = "instanceId"
    type = "S"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }
}

module "eventbridge" {
  source     = "terraform-aws-modules/eventbridge/aws"
  version    = "~> 3.0"
  create_bus = false

  rules = {
    cspm = {
      description = "CSPM findings → SQS"
      event_pattern = jsonencode({
        source      = ["aws.securityhub"]
        detail-type = ["Security Hub Findings - Imported", "Security Hub Findings - Custom"]
        detail      = { findings = { Workflow = { Status = ["NEW"] }, RecordState = ["ACTIVE"], ProductFields = { "aws/securityhub/ProductName" = [{ "anything-but" = "Inspector" }] } } }
      })
    }
    inspector = {
      description = "Inspector findings → SQS"
      event_pattern = jsonencode({
        source      = ["aws.securityhub"]
        detail-type = ["Security Hub Findings - Imported"]
        detail      = { findings = { Workflow = { Status = ["NEW"] }, RecordState = ["ACTIVE"], ProductFields = { "aws/securityhub/ProductName" = ["Inspector"] } } }
      })
    }
    ssm_status = {
      description = "SSM Automation completion"
      event_pattern = jsonencode({
        source      = ["aws.ssm"]
        detail-type = ["EC2 Automation Execution Status-change Notification"]
        detail      = { Status = ["Success", "Failed", "TimedOut", "Cancelled"] }
      })
    }
  }

  targets = {
    cspm       = [{ name = "cspm-queue", arn = module.sqs_cspm.queue_arn }]
    inspector  = [{ name = "inspector-queue", arn = module.sqs_inspector.queue_arn }]
    ssm_status = [{ name = "ssm-callback", arn = module.ssm_callback.lambda_function_arn }]
  }
}


module "cspm" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"

  function_name = "sechub-cspm"
  description   = "Handles CSPM findings — asks Bedrock for the right SSM runbook and runs it"
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  timeout       = var.lambda_timeout
  memory_size   = 256
  source_path   = "${path.module}/lambda_src/dist/cspm"
  tracing_mode  = "Active"

  environment_variables = {
    SNS_TOPIC_ARN    = module.sns.topic_arn
    ENABLED_CONTROLS = jsonencode(var.enabled_controls)
    BEDROCK_MODEL_ID = var.bedrock_model_id
    LAMBDA_ROLE_ARN  = "arn:${local.partition}:iam::${local.account_id}:role/sechub-cspm"
  }

  cloudwatch_logs_retention_in_days = var.log_retention_days
  trusted_entities = ["ssm.amazonaws.com"]

  event_source_mapping = {
    sqs = { event_source_arn = module.sqs_cspm.queue_arn, function_response_types = ["ReportBatchItemFailures"], batch_size = 1 }
  }

  attach_policy_jsons    = true
  number_of_policy_jsons = 2
  policy_jsons = [
    templatefile("${path.module}/policies/cspm-handler.json", {
      partition      = local.partition
      region         = local.region
      account_id     = local.account_id
      sns_topic_arn  = module.sns.topic_arn
      cspm_queue_arn = module.sqs_cspm.queue_arn
    }),
    file("${path.module}/policies/cspm-remediation.json"),
  ]

  create_current_version_allowed_triggers = false
}


module "inspector" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"

  function_name = "sechub-inspector"
  description   = "Handles Inspector CVEs — asks Bedrock for the patch command and runs it via SSM"
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  timeout       = 120
  memory_size   = 128
  source_path   = "${path.module}/lambda_src/dist/inspector"

  environment_variables = { SNS_TOPIC_ARN = module.sns.topic_arn, BEDROCK_MODEL_ID = var.bedrock_model_id, LOCK_TABLE = aws_dynamodb_table.patch_lock.name }
  cloudwatch_logs_retention_in_days = var.log_retention_days

  event_source_mapping = {
    sqs = { event_source_arn = module.sqs_inspector.queue_arn, function_response_types = ["ReportBatchItemFailures"], batch_size = 1 }
  }

  attach_policy_json = true
  policy_json = templatefile("${path.module}/policies/inspector-handler.json", {
    sns_topic_arn       = module.sns.topic_arn
    inspector_queue_arn = module.sqs_inspector.queue_arn
    partition           = local.partition
    region              = local.region
    account_id          = local.account_id
    lock_table_arn      = aws_dynamodb_table.patch_lock.arn
  })

  create_current_version_allowed_triggers = false
}


module "ssm_callback" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "~> 7.0"

  function_name = "sechub-ssm-callback"
  description   = "Forwards SSM Automation completion events to SNS"
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  timeout       = 30
  memory_size   = 128
  source_path   = "${path.module}/lambda_src/dist/ssm-callback"

  environment_variables = { SNS_TOPIC_ARN = module.sns.topic_arn }
  cloudwatch_logs_retention_in_days = var.log_retention_days

  attach_policy_json = true
  policy_json = templatefile("${path.module}/policies/ssm-callback-handler.json", {
    sns_topic_arn = module.sns.topic_arn
    partition     = local.partition
    region        = local.region
    account_id    = local.account_id
  })

  allowed_triggers = {
    eventbridge = { principal = "events.amazonaws.com", source_arn = module.eventbridge.eventbridge_rule_arns["ssm_status"] }
  }

  create_current_version_allowed_triggers = false
}
