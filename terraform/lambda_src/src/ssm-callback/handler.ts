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
  let resolvedFindings: any[] = [];
  if (status === "Success") {
    resolvedFindings = await resolveMatchingFindings(
      executionId,
      "RESOLVED",
      `Remediation confirmed (execution: ${executionId})`,
    );
  } else if (status === "Failed" || status === "TimedOut") {
    resolvedFindings = await resolveMatchingFindings(
      executionId,
      "NOTIFIED",
      `Remediation ${status.toLowerCase()} (execution: ${executionId}): ${failureMessage.slice(0, 256)}`,
    );
  }

  const product = resolvedFindings[0]?.ProductFields?.["aws/securityhub/ProductName"] ?? "";
  const controlId =
    resolvedFindings[0]?.Compliance?.SecurityControlId ?? resolvedFindings[0]?.GeneratorId?.split("/").pop() ?? docName;
  const message =
    status === "Failed"
      ? `Error: ${failureMessage}\n<${execUrl}|View in console>`
      : `Done. <${execUrl}|View in console>`;

  await notifySns(controlId, paramSummary || "unknown", mappedStatus, product, executionId, message);
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
  const title = instanceId;

  const findingIds: { Id: string; ProductArn: string }[] = lockItem.findingIds?.S
    ? JSON.parse(lockItem.findingIds.S)
    : [];

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
        ? `Done. <${cmdUrl}|View in console>`
        : `Error: ${output.slice(0, 500)}\n<${cmdUrl}|View in console>`;
    await notifySns(title, instanceId, mappedStatus, "Inspector", commandId, message);
  }

  try {
    const newCveIds: string[] = lockItem.cveIds?.S ? JSON.parse(lockItem.cveIds.S) : [];
    await ddb.send(new DeleteItemCommand({ TableName: LOCK_TABLE, Key: { instanceId: { S: instanceId } } }));
    if (status === "Success" && !nothingToDo) {
      const now = Math.floor(Date.now() / 1000);
      let existingCveIds: string[] = [];
      try {
        const { Item: patchedItem } = await ddb.send(
          new GetItemCommand({ TableName: LOCK_TABLE, Key: { instanceId: { S: `${instanceId}#patched` } } }),
        );
        existingCveIds = patchedItem?.cveIds?.S ? JSON.parse(patchedItem.cveIds.S) : [];
      } catch {}
      const mergedCveIds = [...new Set([...existingCveIds, ...newCveIds])];
      await ddb.send(
        new PutItemCommand({
          TableName: LOCK_TABLE,
          Item: {
            instanceId: { S: `${instanceId}#patched` },
            patchedAt: { N: String(now) },
            cveIds: { S: JSON.stringify(mergedCveIds) },
            expiresAt: { N: String(now + 7 * 24 * 3600) },
          },
        }),
      );
    }
  } catch (e: any) {
    console.log(JSON.stringify({ event: "RELEASE_LOCK_FAILED", instanceId, error: e.message ?? String(e) }));
  }
}

async function resolveMatchingFindings(
  executionId: string,
  workflowStatus: "RESOLVED" | "NOTIFIED",
  note: string,
  attempt = 0,
): Promise<any[]> {
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

  if (!findings?.length) {
    if (attempt < 4) {
      await new Promise((r) => setTimeout(r, 3000));
      return resolveMatchingFindings(executionId, workflowStatus, note, attempt + 1);
    }
    return [];
  }

  await sechub.send(
    new BatchUpdateFindingsCommand({
      FindingIdentifiers: findings.map((f) => ({ Id: f.Id!, ProductArn: f.ProductArn! })),
      Workflow: { Status: workflowStatus },
      Note: { Text: note.slice(0, 512), UpdatedBy: "sechub-auto-remediation" },
    }),
  );

  return findings;
}

async function notifySns(
  control: string,
  resource: string,
  status: string,
  product: string,
  threadKey: string,
  message: string,
) {
  try {
    await sns.send(
      new PublishCommand({
        TopicArn: SNS_TOPIC_ARN,
        Subject: `[${status}] ${control}`.slice(0, 100),
        Message: JSON.stringify({ control, resource, status, product, threadKey, message }, null, 2),
      }),
    );
  } catch (e: any) {
    console.log(JSON.stringify({ event: "NOTIFY_FAILED", control, error: e.message ?? String(e) }));
  }
}
