import { BatchUpdateFindingsCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { sechubFindingUrl } from "../shared/bedrock.js";

const sechub = new SecurityHubClient({});
const sns = new SNSClient({});

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN!;

export async function handler(event: any) {
  for (const finding of event.detail?.findings ?? []) {
    const product = finding.ProductFields?.["aws/securityhub/ProductName"] ?? finding.ProductName ?? "unknown";
    const resourceId = finding.Resources?.[0]?.Id ?? "unknown";
    const shortId = (finding.Id ?? "").split("/").pop();

    await sns.send(
      new PublishCommand({
        TopicArn: SNS_TOPIC_ARN,
        Subject: `[UNHANDLED] ${product}`.slice(0, 100),
        Message: JSON.stringify({
          control: finding.Title ?? finding.Types?.[0] ?? "unknown",
          resource: resourceId,
          status: "UNHANDLED",
          product,
          threadKey: finding.Id,
          message: `severity: ${finding.Severity?.Label ?? "UNKNOWN"}\ntype: ${finding.Types?.[0] ?? "-"}\nfinding: <${sechubFindingUrl(finding.Id)}|${shortId}>`,
        }),
      }),
    );

    await sechub.send(
      new BatchUpdateFindingsCommand({
        FindingIdentifiers: [{ Id: finding.Id, ProductArn: finding.ProductArn }],
        Workflow: { Status: "NOTIFIED" },
        Note: { Text: "no handler, sent to slack", UpdatedBy: "sechub-auto-remediation" },
      }),
    );

    console.log(JSON.stringify({ event: "UNHANDLED_NOTIFIED", product, resourceId, findingId: finding.Id }));
  }
}
