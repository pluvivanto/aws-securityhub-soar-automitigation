from diagrams import Cluster, Diagram, Edge
from diagrams.aws.security import SecurityHub
from diagrams.aws.integration import Eventbridge, SNS, SQS
from diagrams.aws.compute import Lambda
from diagrams.aws.management import SystemsManager
from diagrams.aws.database import Dynamodb
from diagrams.aws.ml import Bedrock
from diagrams.saas.chat import Slack

with Diagram(
    "",
    filename="docs/architecture",
    show=False,
    direction="LR",
    graph_attr={"fontsize": "24", "bgcolor": "white", "pad": "0.5", "nodesep": "0.7", "ranksep": "1.0"},
    outformat="png",
):
    sechub = SecurityHub("Security Hub")
    eb = Eventbridge("EventBridge")

    with Cluster("CSPM path"):
        sqs_cspm = SQS("SQS")
        dlq_cspm = SQS("DLQ")
        cspm = Lambda("sechub-cspm")
        bedrock_cspm = Bedrock("Bedrock")
        ddb_cache = Dynamodb("DynamoDB\n(runbook cache)")
        ssm_auto = SystemsManager("SSM\nAutomation")

    with Cluster("Inspector path"):
        sqs_insp = SQS("SQS")
        dlq_insp = SQS("DLQ")
        inspector = Lambda("sechub-inspector")
        bedrock_insp = Bedrock("Bedrock")
        ddb_lock = Dynamodb("DynamoDB\n(patch lock)")
        ssm_cmd = SystemsManager("SSM\nRun Command")

    eb_ssm = Eventbridge("EventBridge\n(SSM events)")
    callback = Lambda("sechub-ssm\n-callback")
    sns_topic = SNS("SNS")
    sqs_slack = SQS("SQS")
    dlq_slack = SQS("DLQ")
    slack_fn = Lambda("sechub-slack")
    slack = Slack("Slack")

    # CSPM flow
    sechub >> eb >> sqs_cspm >> cspm >> bedrock_cspm
    cspm >> ssm_auto
    cspm - Edge(style="dashed") - ddb_cache
    sqs_cspm - Edge(style="dashed") - dlq_cspm

    # Inspector flow
    eb >> sqs_insp >> inspector >> bedrock_insp
    inspector >> ssm_cmd
    inspector - Edge(style="dashed") - ddb_lock
    sqs_insp - Edge(style="dashed") - dlq_insp

    # Callback (handles both SSM Automation and Run Command completions)
    ssm_auto >> eb_ssm
    ssm_cmd >> eb_ssm
    eb_ssm >> callback
    callback - Edge(style="dashed") - ddb_lock
    callback >> sns_topic >> sqs_slack >> slack_fn >> slack
    sqs_slack - Edge(style="dashed") - dlq_slack
