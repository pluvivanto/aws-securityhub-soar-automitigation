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

    with Cluster("CSPM Findings"):
        sqs_cspm = SQS("SQS")
        cspm = Lambda("sechub-cspm")
        bedrock_cspm = Bedrock("Bedrock")
        ssm_auto = SystemsManager("SSM\nAutomation")
        eb_ssm = Eventbridge("EventBridge\n(SSM done)")
        callback = Lambda("sechub-ssm\n-callback")

    with Cluster("Inspector Findings"):
        sqs_insp = SQS("SQS")
        inspector = Lambda("sechub-inspector")
        bedrock_insp = Bedrock("Bedrock")
        ddb = Dynamodb("DynamoDB\n(lock)")
        ssm_cmd = SystemsManager("SSM\nRun Command")

    sns_topic = SNS("SNS")
    slack_fn = Lambda("sechub-slack")
    slack = Slack("Slack")

    # CSPM flow
    sechub >> eb >> sqs_cspm >> cspm >> bedrock_cspm
    cspm >> ssm_auto >> eb_ssm >> callback >> sns_topic >> slack_fn >> slack

    # Inspector flow
    eb >> sqs_insp >> inspector >> bedrock_insp
    inspector >> ssm_cmd
    inspector >> sns_topic
    inspector - Edge(style="dashed") - ddb
