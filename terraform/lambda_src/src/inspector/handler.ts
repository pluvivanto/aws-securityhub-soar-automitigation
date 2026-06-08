import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DeleteItemCommand,
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { BatchUpdateFindingsCommand, GetFindingsCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { DescribeInstanceInformationCommand, SendCommandCommand, SSMClient } from "@aws-sdk/client-ssm";
import { callBedrock, sechubFindingUrl } from "../shared/bedrock.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROMPT = readFileSync(join(__dirname, "prompts", "patch-command.txt"), "utf-8");

const ssm = new SSMClient({});
const sns = new SNSClient({});
const sechub = new SecurityHubClient({});
const ddb = new DynamoDBClient({});

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN!;
const LOCK_TABLE = process.env.LOCK_TABLE!;
const REGION = process.env.AWS_REGION ?? "us-east-1";
const ACCOUNT_ID = process.env.ACCOUNT_ID!;

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
      console.log(JSON.stringify({ event: "NOT_SSM_MANAGED", instanceId }));
      return { status: "SKIPPED", reason: "not SSM managed" };
    }

    const allFindings = await getAllCveFindings(instanceId);
    if (allFindings.length === 0) {
      return { status: "SKIPPED", reason: "no NEW CVE findings for instance" };
    }

    const { patchedAt, patchedCveIds } = await getPatchRecord(instanceId);
    let candidateFindings = allFindings;
    if (patchedAt) {
      candidateFindings = candidateFindings.filter(
        (f) => new Date(f.LastObservedAt ?? f.CreatedAt).getTime() / 1000 > patchedAt,
      );
    }
    if (patchedCveIds.size > 0) {
      candidateFindings = candidateFindings.filter((f) => {
        const cveId = extractCveId(f);
        return !cveId || !patchedCveIds.has(cveId);
      });
    }
    if (candidateFindings.length === 0) {
      console.log(
        JSON.stringify({ event: "STALE_FINDINGS_SKIPPED", instanceId, count: allFindings.length, patchedAt }),
      );
      return { status: "SKIPPED", reason: "all findings already patched" };
    }

    console.log(JSON.stringify({ event: "BATCH_PATCH", instanceId, count: candidateFindings.length }));

    const summaries = candidateFindings.map((f) => ({
      Title: f.Title ?? "",
      RemediationText: f.Remediation?.Recommendation?.Text ?? "",
      VulnerablePackages: (f.Vulnerabilities ?? []).flatMap((v: any) => v.VulnerablePackages ?? []),
    }));

    const decision: Record<string, string> = await callBedrock(
      PROMPT.replace("{{findings}}", JSON.stringify(summaries, null, 2)),
      512,
    );
    console.log(JSON.stringify({ event: "BEDROCK_PATCH_DECISION", instanceId, ...decision }));

    if (decision.action !== "PATCH") {
      return { status: "SKIPPED", reason: decision.reason };
    }

    const findingIds = candidateFindings.map((f) => ({ Id: f.Id!, ProductArn: f.ProductArn! }));
    await storePatchInfo(instanceId, candidateFindings);

    for (let i = 0; i < findingIds.length; i += 100) {
      await sechub.send(
        new BatchUpdateFindingsCommand({
          FindingIdentifiers: findingIds.slice(i, i + 100),
          Workflow: { Status: "NOTIFIED" as any },
          Note: { Text: `patching ${candidateFindings.length} CVEs`, UpdatedBy: "sechub-auto-remediation" },
        }),
      );
    }

    const { Command } = await ssm.send(
      new SendCommandCommand({
        InstanceIds: [instanceId],
        DocumentName: "AWS-RunShellScript",
        Parameters: { commands: [decision.command] },
        TimeoutSeconds: 600,
        Comment: `Auto-patch: ${candidateFindings.length} CVEs on ${instanceId}`,
      }),
    );

    const commandId = Command?.CommandId ?? "unknown";
    const cveList = "\n" + candidateFindings.map((f) => `• <${sechubFindingUrl(f.Id!)}|${f.Title ?? f.Id}>`).join("\n");
    await notify(
      instanceId,
      instanceId,
      "PATCH_STARTED",
      "Inspector",
      commandId,
      `Patching ${candidateFindings.length} CVEs on \`${instanceId}\`${cveList}\n<${ssmCommandUrl(commandId)}|View in console>`,
    );
    console.log(
      JSON.stringify({ event: "PATCH_DISPATCHED", instanceId, commandId, cveCount: candidateFindings.length }),
    );
    success = true;
    return { status: "PATCH_DISPATCHED", instanceId, commandId, cveCount: candidateFindings.length };
  } finally {
    if (!success) {
      await releaseLock(instanceId);
    }
  }
}

async function getAllCveFindings(instanceId: string): Promise<any[]> {
  const filters = {
    WorkflowStatus: [{ Value: "NEW", Comparison: "EQUALS" as const }],
    RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" as const }],
    ProductFields: [{ Key: "aws/securityhub/ProductName", Value: "Inspector", Comparison: "EQUALS" as const }],
    ResourceId: [
      { Value: `arn:aws:ec2:${REGION}:${ACCOUNT_ID}:instance/${instanceId}`, Comparison: "EQUALS" as const },
    ],
  };
  const all: any[] = [];
  let nextToken: string | undefined;
  do {
    const { Findings, NextToken } = await sechub.send(
      new GetFindingsCommand({ Filters: filters, MaxResults: 100, NextToken: nextToken }),
    );
    all.push(...(Findings ?? []));
    nextToken = NextToken;
  } while (nextToken);
  return all;
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

function extractCveId(finding: any): string | null {
  const match = (finding.Title ?? "").match(/CVE-\d{4}-\d+/);
  return match ? match[0] : null;
}

async function storePatchInfo(instanceId: string, findings: any[]) {
  const findingIds = findings.map((f) => ({ Id: f.Id!, ProductArn: f.ProductArn! }));
  const cveIds = findings.map((f) => extractCveId(f)).filter(Boolean);
  await ddb.send(
    new UpdateItemCommand({
      TableName: LOCK_TABLE,
      Key: { instanceId: { S: instanceId } },
      UpdateExpression: "SET findingIds = :ids, cveIds = :cveIds",
      ExpressionAttributeValues: {
        ":ids": { S: JSON.stringify(findingIds) },
        ":cveIds": { S: JSON.stringify(cveIds) },
      },
    }),
  );
}

async function getPatchRecord(instanceId: string): Promise<{ patchedAt: number | null; patchedCveIds: Set<string> }> {
  try {
    const { Item } = await ddb.send(
      new GetItemCommand({ TableName: LOCK_TABLE, Key: { instanceId: { S: `${instanceId}#patched` } } }),
    );
    const patchedAt = Number(Item?.patchedAt?.N ?? 0) || null;
    const patchedCveIds = new Set<string>(Item?.cveIds?.S ? JSON.parse(Item.cveIds.S) : []);
    return { patchedAt, patchedCveIds };
  } catch (e: any) {
    console.log(JSON.stringify({ event: "GET_PATCH_RECORD_FAILED", instanceId, error: e.message ?? String(e) }));
    return { patchedAt: null, patchedCveIds: new Set() };
  }
}

async function releaseLock(instanceId: string) {
  try {
    await ddb.send(new DeleteItemCommand({ TableName: LOCK_TABLE, Key: { instanceId: { S: instanceId } } }));
  } catch (e: any) {
    console.log(JSON.stringify({ event: "RELEASE_LOCK_FAILED", instanceId, error: e.message ?? String(e) }));
  }
}

async function isInstanceManaged(instanceId: string): Promise<boolean> {
  try {
    const { InstanceInformationList } = await ssm.send(
      new DescribeInstanceInformationCommand({ Filters: [{ Key: "InstanceIds", Values: [instanceId] }] }),
    );
    return (InstanceInformationList?.length ?? 0) > 0;
  } catch (e: any) {
    console.log(JSON.stringify({ event: "DESCRIBE_INSTANCE_FAILED", instanceId, error: e.message ?? String(e) }));
    return false;
  }
}

async function notify(
  control: string,
  resourceId: string,
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
        Message: JSON.stringify({ control, resource: resourceId, status, product, threadKey, message }, null, 2),
      }),
    );
  } catch (e: any) {
    console.log(JSON.stringify({ event: "NOTIFY_FAILED", control, status, error: e.message ?? String(e) }));
  }
}
