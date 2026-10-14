# sechub-auto-remediation

Auto-fixes AWS Security Hub findings using Bedrock to pick the right remediation. No static mapping needed. New controls and CVEs are handled without code changes.

![Architecture](./docs/architecture.svg)

## Lambdas

| Name | Purpose |
| --- | --- |
| `sechub-cspm` | Asks Bedrock which SSM runbook to run, then runs it |
| `sechub-inspector` | Patches CVE-affected EC2 instances via SSM |
| `sechub-ssm-callback` | Picks up SSM completion events, resolves findings, sends to SNS |
| `sechub-unhandled` | Sends HIGH+ findings with no handler to Slack |
| `sechub-slack` | Forwards SNS messages to Slack |

## Getting started

```bash
cd terraform/lambda_src
npm install
npm run build
cd ..
terraform init
terraform apply
```

Required variables go in `terraform.tfvars`:

```hcl
bedrock_model_id     = "global.anthropic.(...)"
slack_bot_token      = "xoxb-..."
slack_channel_id     = "C..."
slack_signing_secret = "..."
```

## Variables

| Name | Default | What it does |
| --- | --- | --- |
| `aws_region` | `us-east-1` | Where to deploy |
| `enabled_controls` | `["*"]` | Which CSPM controls to remediate (`["*"]` = all) |
| `bedrock_model_id` | — | Which Bedrock model to use |
| `slack_bot_token` | — | Slack bot token |
| `slack_channel_id` | — | Slack channel ID |
| `slack_signing_secret` | — | Slack app signing secret |
| `log_retention_days` | `30` | CloudWatch log retention |
| `lambda_timeout` | `300` | Lambda timeout in seconds |
