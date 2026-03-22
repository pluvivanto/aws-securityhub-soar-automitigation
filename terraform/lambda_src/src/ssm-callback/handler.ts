import { BatchUpdateFindingsCommand, GetFindingsCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { GetAutomationExecutionCommand, SSMClient } from "@aws-sdk/client-ssm";

const ssm = new SSMClient({});
const sechub = new SecurityHubClient({});
const sns = new SNSClient({});
const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN!;
const OUR_ROLE_PATTERN = "sechub-cspm";

const STATUS_MAP: Record<string, string> = {
  Success: "REMEDIATION_COMPLETE",
  Failed: "REMEDIATION_FAILED",
  TimedOut: "REMEDIATION_TIMED_OUT",
  Cancelled: "REMEDIATION_CANCELLED",
};

export async function handler(event: any) {
  const { ExecutionId: executionId = "unknown", Status: status = "unknown" } = event.detail ?? {};

  let docName = event.detail?.Definition ?? "unknown";
  let params: Record<string, string[]> = {};
  let failureMessage = "";
  let executedBy = "";

  try {
    const { AutomationExecution: exec } = await ssm.send(
      new GetAutomationExecutionCommand({ AutomationExecutionId: executionId }),
    );
    docName = exec?.DocumentName ?? docName;
    failureMessage = exec?.FailureMessage ?? "";
    params = (exec?.Parameters as Record<string, string[]>) ?? {};
    executedBy = exec?.ExecutedBy ?? "";
  } catch {}

  // Only notify for executions started by our CSPM handler
  if (!executedBy.includes(OUR_ROLE_PATTERN)) return;

  const paramSummary = Object.entries(params)
    .filter(([k, v]) => k !== "AutomationAssumeRole" && v?.length)
    .map(([k, v]) => `${k}=${v[0]}`)
    .join(", ");

  const REGION = process.env.AWS_REGION ?? "us-east-1";
  const execUrl = `https://${REGION}.console.aws.amazon.com/systems-manager/automation/execution/${executionId}?region=${REGION}`;

  const mappedStatus = STATUS_MAP[status] ?? status;
  const message =
    status === "Failed"
      ? `${docName}\nParams: ${paramSummary}\nError: ${failureMessage}\n<${execUrl}|View in console>`
      : `${docName}\nParams: ${paramSummary}\n<${execUrl}|View in console>`;

  // On success, mark the finding as RESOLVED
  if (status === "Success") {
    await resolveMatchingFindings(executionId);
  }

  await sns.send(
    new PublishCommand({
      TopicArn: SNS_TOPIC_ARN,
      Subject: `[${mappedStatus}] ${docName}`,
      Message: JSON.stringify(
        { control: docName, resource: paramSummary || "unknown", status: mappedStatus, message },
        null,
        2,
      ),
    }),
  );
}

async function resolveMatchingFindings(executionId: string) {
  // Find NOTIFIED findings whose note contains this execution ID
  try {
    const { Findings: findings } = await sechub.send(
      new GetFindingsCommand({
        Filters: {
          WorkflowStatus: [{ Value: "NOTIFIED", Comparison: "EQUALS" }],
          NoteText: [{ Value: executionId, Comparison: "PREFIX" }],
          RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
        },
        MaxResults: 5,
      }),
    );

    if (!findings?.length) return;

    await sechub.send(
      new BatchUpdateFindingsCommand({
        FindingIdentifiers: findings.map((f) => ({ Id: f.Id!, ProductArn: f.ProductArn! })),
        Workflow: { Status: "RESOLVED" },
        Note: { Text: `Remediation confirmed (execution: ${executionId})`, UpdatedBy: "sechub-auto-remediation" },
      }),
    );
  } catch {}
}
