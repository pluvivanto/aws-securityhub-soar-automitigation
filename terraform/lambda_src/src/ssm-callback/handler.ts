import { DeleteItemCommand, DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { BatchUpdateFindingsCommand, GetFindingsCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { GetAutomationExecutionCommand, GetCommandInvocationCommand, SSMClient } from "@aws-sdk/client-ssm";

const ssm = new SSMClient({});
const sechub = new SecurityHubClient({});
const sns = new SNSClient({});
const ddb = new DynamoDBClient({});
const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN!;
const LOCK_TABLE = process.env.LOCK_TABLE ?? "";
const REGION = process.env.AWS_REGION ?? "us-east-1";
const OUR_ROLE_PATTERN = "sechub-cspm";

const STATUS_MAP: Record<string, string> = {
  Success: "REMEDIATION_COMPLETE",
  Failed: "REMEDIATION_FAILED",
  TimedOut: "REMEDIATION_TIMED_OUT",
  Cancelled: "REMEDIATION_CANCELLED",
};

const COMMAND_STATUS_MAP: Record<string, string> = {
  Success: "PATCH_COMPLETE",
  Failed: "PATCH_FAILED",
  TimedOut: "PATCH_FAILED",
  Cancelled: "PATCH_FAILED",
};

export async function handler(event: any) {
  const detailType = event["detail-type"] ?? "";

  if (detailType === "EC2 Automation Execution Status-change Notification") {
    return handleAutomationCallback(event);
  }
  if (detailType === "EC2 Command Invocation Status-change Notification") {
    return handleRunCommandCallback(event);
  }

  console.log(JSON.stringify({ event: "UNKNOWN_EVENT_TYPE", detailType }));
}

async function handleAutomationCallback(event: any) {
  const { ExecutionId: executionId = "unknown", Status: status = "unknown" } = event.detail ?? {};

  let docName = event.detail?.Definition ?? "unknown";
  let params: Record<string, string[]> = {};
  let failureMessage = "";
  let executedBy = "";

  const { AutomationExecution: exec } = await ssm.send(
    new GetAutomationExecutionCommand({ AutomationExecutionId: executionId }),
  );
  docName = exec?.DocumentName ?? docName;
  failureMessage = exec?.FailureMessage ?? "";
  params = (exec?.Parameters as Record<string, string[]>) ?? {};
  executedBy = exec?.ExecutedBy ?? "";

  if (!executedBy.includes(OUR_ROLE_PATTERN)) return;

  const paramSummary = Object.entries(params)
    .filter(([k, v]) => k !== "AutomationAssumeRole" && v?.length)
    .map(([k, v]) => `${k}=${v[0]}`)
    .join(", ");

  const execUrl = `https://${REGION}.console.aws.amazon.com/systems-manager/automation/execution/${executionId}?region=${REGION}`;
  const mappedStatus = STATUS_MAP[status] ?? status;
  const message =
    status === "Failed"
      ? `${docName}\nexecution: ${executionId}\nParams: ${paramSummary}\nError: ${failureMessage}\n<${execUrl}|View in console>`
      : `${docName}\nexecution: ${executionId}\nParams: ${paramSummary}\n<${execUrl}|View in console>`;

  if (status === "Success") {
    await resolveMatchingFindings(executionId, "RESOLVED", `Remediation confirmed (execution: ${executionId})`);
  } else if (status === "Failed" || status === "TimedOut") {
    await resolveMatchingFindings(
      executionId,
      "NOTIFIED",
      `Remediation ${status.toLowerCase()} (execution: ${executionId}): ${failureMessage.slice(0, 256)}`,
    );
  }

  await notifySns(docName, paramSummary || "unknown", mappedStatus, message);
}

async function handleRunCommandCallback(event: any) {
  const commandId = event.detail?.["command-id"] ?? "unknown";
  const status = event.detail?.status ?? "unknown";
  const docName = event.detail?.["document-name"] ?? "";
  const instanceId = event.detail?.["instance-id"] ?? "unknown";

  if (docName !== "AWS-RunShellScript") return;
  if (!LOCK_TABLE || instanceId === "unknown") return;

  let lockItem: Record<string, any> | undefined;
  try {
    const { Item } = await ddb.send(
      new GetItemCommand({ TableName: LOCK_TABLE, Key: { instanceId: { S: instanceId } } }),
    );
    lockItem = Item;
  } catch {}
  if (!lockItem) return;

  const cmdUrl = `https://${REGION}.console.aws.amazon.com/systems-manager/run-command/${commandId}?region=${REGION}`;
  const mappedStatus = COMMAND_STATUS_MAP[status] ?? status;
  const title = `Patch - ${instanceId}`;

  const findingIds: { Id: string; ProductArn: string }[] = lockItem.findingIds?.S
    ? JSON.parse(lockItem.findingIds.S)
    : [];
  const titles: string[] = lockItem.titles?.S ? JSON.parse(lockItem.titles.S) : [];
  const cveList =
    titles.length > 0
      ? "\n" +
        titles
          .slice(0, 20)
          .map((t) => `• ${t}`)
          .join("\n") +
        (titles.length > 20 ? `\n• ...and ${titles.length - 20} more` : "")
      : "";

  let output = "";
  let nothingToDo = false;
  try {
    const inv = await ssm.send(new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: instanceId }));
    const stdOut = inv.StandardOutputContent ?? "";
    const stdErr = inv.StandardErrorContent ?? "";
    output = stdErr || stdOut;
    nothingToDo = status === "Success" && stdOut.includes("Nothing to do");
  } catch (e: any) {
    console.log(JSON.stringify({ event: "GET_INVOCATION_FAILED", commandId, error: e.message ?? String(e) }));
  }

  if (status === "Success") {
    if (findingIds.length > 0) {
      try {
        for (let i = 0; i < findingIds.length; i += 100) {
          await sechub.send(
            new BatchUpdateFindingsCommand({
              FindingIdentifiers: findingIds.slice(i, i + 100),
              Workflow: { Status: "RESOLVED" },
              Note: { Text: `Patch completed (command: ${commandId})`, UpdatedBy: "sechub-auto-remediation" },
            }),
          );
        }
        console.log(
          JSON.stringify({ event: "FINDINGS_RESOLVED", instanceId, count: findingIds.length, commandId, nothingToDo }),
        );
      } catch (e: any) {
        console.log(JSON.stringify({ event: "RESOLVE_FINDINGS_FAILED", instanceId, error: e.message ?? String(e) }));
      }
    }
  }

  console.log(JSON.stringify({ event: "COMMAND_CALLBACK", commandId, instanceId, status: mappedStatus, nothingToDo }));

  if (!nothingToDo) {
    const message =
      status === "Success"
        ? `Patched \`${instanceId}\` (${findingIds.length} CVEs)${cveList}\n<${cmdUrl}|View in console>`
        : `Failed to patch \`${instanceId}\` (${findingIds.length} CVEs)${cveList}\nError: ${output.slice(0, 300)}\n<${cmdUrl}|View in console>`;
    await notifySns(title, instanceId, mappedStatus, message);
  }

  try {
    await ddb.send(new DeleteItemCommand({ TableName: LOCK_TABLE, Key: { instanceId: { S: instanceId } } }));
    if (status === "Success" && !nothingToDo) {
      const now = Math.floor(Date.now() / 1000);
      await ddb.send(
        new PutItemCommand({
          TableName: LOCK_TABLE,
          Item: {
            instanceId: { S: `${instanceId}#patched` },
            patchedAt: { N: String(now) },
            expiresAt: { N: String(now + 3600) },
          },
        }),
      );
    }
  } catch (e: any) {
    console.log(JSON.stringify({ event: "RELEASE_LOCK_FAILED", instanceId, error: e.message ?? String(e) }));
  }
}

async function resolveMatchingFindings(executionId: string, workflowStatus: "RESOLVED" | "NOTIFIED", note: string) {
  const { Findings: findings } = await sechub.send(
    new GetFindingsCommand({
      Filters: {
        WorkflowStatus: [{ Value: "NOTIFIED", Comparison: "EQUALS" }],
        NoteText: [{ Value: executionId, Comparison: "PREFIX" }],
        RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
      },
      MaxResults: 100,
    }),
  );

  if (!findings?.length) return;

  await sechub.send(
    new BatchUpdateFindingsCommand({
      FindingIdentifiers: findings.map((f) => ({ Id: f.Id!, ProductArn: f.ProductArn! })),
      Workflow: { Status: workflowStatus },
      Note: { Text: note.slice(0, 512), UpdatedBy: "sechub-auto-remediation" },
    }),
  );
}

async function notifySns(control: string, resource: string, status: string, message: string) {
  try {
    await sns.send(
      new PublishCommand({
        TopicArn: SNS_TOPIC_ARN,
        Subject: `[${status}] ${control}`.slice(0, 100),
        Message: JSON.stringify({ control, resource, status, message }, null, 2),
      }),
    );
  } catch (e: any) {
    console.log(JSON.stringify({ event: "NOTIFY_FAILED", control, error: e.message ?? String(e) }));
  }
}
