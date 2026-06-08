locals {
  alarm_lambdas = ["sechub-cspm", "sechub-inspector", "sechub-ssm-callback"]
  alarm_dlqs    = ["sechub-cspm-dlq", "sechub-inspector-dlq"]
  alarm_queues  = ["sechub-cspm-queue", "sechub-inspector-queue"]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each            = toset(local.alarm_lambdas)
  alarm_name          = "${each.value}-errors"
  alarm_description   = "Lambda ${each.value} surfaced errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value }
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 300
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [module.sns.topic_arn]
  ok_actions          = [module.sns.topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  for_each            = toset(local.alarm_dlqs)
  alarm_name          = "${each.value}-depth"
  alarm_description   = "Messages landed in ${each.value}"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = each.value }
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [module.sns.topic_arn]
  ok_actions          = [module.sns.topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "queue_age" {
  for_each            = toset(local.alarm_queues)
  alarm_name          = "${each.value}-oldest-age"
  alarm_description   = "Oldest message in ${each.value} aging out"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  dimensions          = { QueueName = each.value }
  statistic           = "Maximum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 900
  period              = 60
  evaluation_periods  = 5
  treat_missing_data  = "notBreaching"
  alarm_actions       = [module.sns.topic_arn]
  ok_actions          = [module.sns.topic_arn]
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "sechub-auto-remediation"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6
        properties = {
          title  = "Lambda invocations"
          region = local.region
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "sechub-cspm", { stat = "Sum" }],
            ["...", "sechub-inspector", { stat = "Sum" }],
            ["...", "sechub-ssm-callback", { stat = "Sum" }],
            ["...", "sechub-slack", { stat = "Sum" }],
          ]
          period = 300
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6
        properties = {
          title  = "Lambda errors"
          region = local.region
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", "sechub-cspm", { stat = "Sum", color = "#d62728" }],
            ["...", "sechub-inspector", { stat = "Sum", color = "#ff7f0e" }],
            ["...", "sechub-ssm-callback", { stat = "Sum", color = "#9467bd" }],
          ]
          period = 300
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6
        properties = {
          title  = "Lambda duration (avg ms)"
          region = local.region
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", "sechub-cspm", { stat = "Average" }],
            ["...", "sechub-inspector", { stat = "Average" }],
            ["...", "sechub-ssm-callback", { stat = "Average" }],
          ]
          period = 300
        }
      },
      {
        type = "metric", x = 12, y = 6, width = 12, height = 6
        properties = {
          title  = "Lambda throttles"
          region = local.region
          metrics = [
            ["AWS/Lambda", "Throttles", "FunctionName", "sechub-cspm", { stat = "Sum", color = "#d62728" }],
            ["...", "sechub-inspector", { stat = "Sum", color = "#ff7f0e" }],
          ]
          period = 300
        }
      },
      {
        type = "metric", x = 0, y = 12, width = 12, height = 6
        properties = {
          title  = "SQS queue depth"
          region = local.region
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "sechub-cspm-queue"],
            ["...", "sechub-inspector-queue"],
          ]
          period = 60
        }
      },
      {
        type = "metric", x = 12, y = 12, width = 12, height = 6
        properties = {
          title  = "DLQ messages"
          region = local.region
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "sechub-cspm-dlq", { color = "#d62728" }],
            ["...", "sechub-inspector-dlq", { color = "#ff7f0e" }],
          ]
          period = 60
        }
      },
      {
        type = "metric", x = 0, y = 18, width = 12, height = 6
        properties = {
          title  = "SQS oldest message age (s)"
          region = local.region
          metrics = [
            ["AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName", "sechub-cspm-queue"],
            ["...", "sechub-inspector-queue"],
          ]
          period = 60
        }
      },
      {
        type = "metric", x = 12, y = 18, width = 12, height = 6
        properties = {
          title  = "Lambda concurrency"
          region = local.region
          metrics = [
            ["AWS/Lambda", "ConcurrentExecutions", "FunctionName", "sechub-cspm"],
            ["...", "sechub-inspector"],
          ]
          period = 60
        }
      },
    ]
  })
}
