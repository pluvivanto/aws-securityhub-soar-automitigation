import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";
import { DeleteItemCommand, DynamoDBClient, PutItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { BatchUpdateFindingsCommand, GetFindingsCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { DescribeInstanceInformationCommand, SendCommandCommand, SSMClient } from "@aws-sdk/client-ssm";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROMPT = readFileSync(join(__dirname, "prompts", "patch-command.txt"), "utf-8");

const ssm = new SSMClient({});
const sns = new SNSClient({});
const sechub = new SecurityHubClient({});
const bedrock = new BedrockRuntimeClient({});
const ddb = new DynamoDBClient({});

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN!;
const MODEL_ID = process.env.BEDROCK_MODEL_ID!;
const LOCK_TABLE = process.env.LOCK_TABLE!;
const REGION = process.env.AWS_REGION ?? "us-east-1";

function ssmCommandUrl(commandId: string) {
  return `https://${REGION}.console.aws.amazon.com/systems-manager/run-command/${commandId}?region=${REGION}`;
}

export async function handler(event: any) {
  const findings: any[] = [];
  if (event.Records) {
    for (const record of event.Records) {
      const body = JSON.parse(record.body);
      findings.push(...(body.detail?.findings ?? []));
    }
  } else if (event.finding) {
    findings.push(event.finding);
  }
  const results = [];
  for (const finding of findings) {
    results.push(await processFinding(finding));
  }
  return { processed: results.length, results };
}

async function processFinding(triggerFinding: any) {
  const resourceId = triggerFinding.Resources?.[0]?.Id ?? "";
  const instanceId = resourceId.includes("instance/") ? resourceId.split("instance/")[1] : "";
  if (!instanceId) return { status: "SKIPPED", reason: "not an EC2 instance" };

  const workflowStatus = triggerFinding.Workflow?.Status ?? "NEW";
  if (workflowStatus !== "NEW") {
    console.log(
      JSON.stringify({ event: "ALREADY_PROCESSED", instanceId, findingId: triggerFinding.Id, workflowStatus }),
    );
    return { status: "SKIPPED", reason: `finding already ${workflowStatus}` };
  }

  console.log(JSON.stringify({ event: "PATCH_REQUESTED", instanceId, title: triggerFinding.Title }));

  // Acquire lock — if another invocation is patching this instance, fail so SQS retries
  const locked = await acquireLock(instanceId);
  if (!locked) {
    throw new Error(`${instanceId} is locked, retry pending`);
  }

  let success = false;
  try {
    if (!(await isInstanceManaged(instanceId))) {
      await notify(`CVEs - ${instanceId}`, instanceId, "SKIPPED", `Instance ${instanceId} is not managed by SSM`);
      return { status: "SKIPPED", reason: "not SSM managed" };
    }

    const allFindings = await getAllCveFindings(instanceId);
    if (allFindings.length === 0) {
      return { status: "SKIPPED", reason: "no NEW CVE findings for instance" };
    }

    console.log(JSON.stringify({ event: "BATCH_PATCH", instanceId, count: allFindings.length }));

    const summaries = allFindings.map((f) => ({
      Title: f.Title ?? "",
      RemediationText: f.Remediation?.Recommendation?.Text ?? "",
      VulnerablePackages: (f.Vulnerabilities ?? []).flatMap((v: any) => v.VulnerablePackages ?? []),
    }));

    const decision: Record<string, string> = await callBedrock(
      PROMPT.replace("{{findings}}", JSON.stringify(summaries, null, 2)),
    );
    console.log(JSON.stringify({ event: "BEDROCK_PATCH_DECISION", instanceId, ...decision }));

    if (decision.action !== "PATCH") {
      await notify(`CVEs - ${instanceId}`, instanceId, "SKIPPED", decision.reason ?? "Bedrock skipped");
      return { status: "SKIPPED", reason: decision.reason };
    }

    const findingIds = allFindings.map((f) => ({ Id: f.Id!, ProductArn: f.ProductArn! }));
    await storeFindingIds(instanceId, findingIds);

    await sechub.send(
      new BatchUpdateFindingsCommand({
        FindingIdentifiers: findingIds,
        Workflow: { Status: "NOTIFIED" as any },
        Note: { Text: `patching ${allFindings.length} CVEs`, UpdatedBy: "sechub-auto-remediation" },
      }),
    );

    const { Command } = await ssm.send(
      new SendCommandCommand({
        InstanceIds: [instanceId],
        DocumentName: "AWS-RunShellScript",
        Parameters: { commands: [decision.command] },
        TimeoutSeconds: 600,
        Comment: `Auto-patch: ${allFindings.length} CVEs on ${instanceId}`,
      }),
    );

    const commandId = Command?.CommandId ?? "unknown";
    await notify(
      `CVEs - ${instanceId}`,
      instanceId,
      "PATCH_STARTED",
      `Patching ${allFindings.length} CVEs on \`${instanceId}\`\n<${ssmCommandUrl(commandId)}|View in console>`,
    );

    console.log(JSON.stringify({ event: "PATCH_DISPATCHED", instanceId, commandId, cveCount: allFindings.length }));
    success = true;
    return { status: "PATCH_DISPATCHED", instanceId, commandId, cveCount: allFindings.length };
  } finally {
    if (!success) {
      await releaseLock(instanceId);
    }
  }
}

async function getAllCveFindings(instanceId: string): Promise<any[]> {
  try {
    const { Findings } = await sechub.send(
      new GetFindingsCommand({
        Filters: {
          WorkflowStatus: [{ Value: "NEW", Comparison: "EQUALS" }],
          RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
          ProductFields: [{ Key: "aws/securityhub/ProductName", Value: "Inspector", Comparison: "EQUALS" }],
          ResourceId: [{ Value: instanceId, Comparison: "CONTAINS" }],
        },
        MaxResults: 100,
      }),
    );
    return Findings ?? [];
  } catch (e: any) {
    console.log(JSON.stringify({ event: "GET_FINDINGS_FAILED", instanceId, error: e.message ?? String(e) }));
    return [];
  }
}

async function acquireLock(instanceId: string): Promise<boolean> {
  try {
    await ddb.send(
      new PutItemCommand({
        TableName: LOCK_TABLE,
        Item: {
          instanceId: { S: instanceId },
          expiresAt: { N: String(Math.floor(Date.now() / 1000) + 900) },
        },
        ConditionExpression: "attribute_not_exists(instanceId)",
      }),
    );
    return true;
  } catch (e: any) {
    if (e.name === "ConditionalCheckFailedException") return false;
    throw e;
  }
}

async function storeFindingIds(instanceId: string, findingIds: { Id: string; ProductArn: string }[]) {
  try {
    await ddb.send(
      new UpdateItemCommand({
        TableName: LOCK_TABLE,
        Key: { instanceId: { S: instanceId } },
        UpdateExpression: "SET findingIds = :ids",
        ExpressionAttributeValues: { ":ids": { S: JSON.stringify(findingIds) } },
      }),
    );
  } catch (e: any) {
    console.log(JSON.stringify({ event: "STORE_FINDING_IDS_FAILED", instanceId, error: e.message ?? String(e) }));
  }
}

async function releaseLock(instanceId: string) {
  try {
    await ddb.send(new DeleteItemCommand({ TableName: LOCK_TABLE, Key: { instanceId: { S: instanceId } } }));
  } catch {}
}

async function callBedrock(prompt: string): Promise<any> {
  const res = await bedrock.send(
    new InvokeModelCommand({
      modelId: MODEL_ID,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        anthropic_version: "bedrock-2023-05-31",
        max_tokens: 512,
        temperature: 0,
        messages: [{ role: "user", content: prompt }],
      }),
    }),
  );
  let text: string = JSON.parse(new TextDecoder().decode(res.body)).content[0].text.trim();
  if (text.startsWith("```"))
    text = text
      .split("\n")
      .slice(1)
      .join("\n")
      .replace(/```\s*$/, "")
      .trim();
  return JSON.parse(text);
}

async function isInstanceManaged(instanceId: string): Promise<boolean> {
  try {
    const { InstanceInformationList } = await ssm.send(
      new DescribeInstanceInformationCommand({ Filters: [{ Key: "InstanceIds", Values: [instanceId] }] }),
    );
    return (InstanceInformationList?.length ?? 0) > 0;
  } catch {
    return false;
  }
}

async function notify(control: string, resourceId: string, status: string, message: string) {
  try {
    await sns.send(
      new PublishCommand({
        TopicArn: SNS_TOPIC_ARN,
        Subject: `[${status}] ${control}`.slice(0, 100),
        Message: JSON.stringify({ control, resource: resourceId, status, message }, null, 2),
      }),
    );
  } catch {}
}
