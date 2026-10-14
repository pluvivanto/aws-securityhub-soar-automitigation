# sechub-auto-remediation

Serverless SOAR that auto-remediates AWS Security Hub findings. An LLM proposes the fix, and a human-in-the-loop approves it in Slack before it runs.

![Architecture](./docs/architecture.svg)

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

The Slack app needs the `chat:write` and `reactions:write` scopes. After `apply`, turn on Interactivity and set the Request URL to `terraform output -raw slack_interactivity_url`.

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
