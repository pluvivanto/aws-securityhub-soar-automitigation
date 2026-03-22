import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";
import { DeleteItemCommand, DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { BatchUpdateFindingsCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import {
  DescribeInstanceInformationCommand,
  GetCommandInvocationCommand,
  SendCommandCommand,
  SSMClient,
} from "@aws-sdk/client-ssm";

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

function ssmAutomationUrl(executionId: string) {
  return `https://${REGION}.console.aws.amazon.com/systems-manager/automation/execution/${executionId}?region=${REGION}`;
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

async function processFinding(finding: any) {
  const resourceId = finding.Resources?.[0]?.Id ?? "";
  const instanceId = resourceId.includes("instance/") ? resourceId.split("instance/")[1] : "";
  if (!instanceId) return { status: "SKIPPED", reason: "not an EC2 instance" };

  const title = finding.Title ?? "Unknown CVE";
  const severity = finding.Severity?.Label ?? "UNKNOWN";
  const cveId = title.split(" - ")[0];
  const packages = title.includes(" - ") ? title.split(" - ").slice(1).join(" - ") : "unknown";
  const notifyTitle = `${cveId} - ${instanceId}`;

  console.log(JSON.stringify({ event: "PATCH_REQUESTED", instanceId, title, severity }));

  // Acquire lock — if another invocation is patching this instance, fail so SQS retries
  const locked = await acquireLock(instanceId);
  if (!locked) {
    throw new Error(`Instance ${instanceId} is locked — will retry via SQS`);
  }

  try {
    // Mark finding so it doesn't re-trigger
    const findingId = finding.Id ?? "";
    const productArn = finding.ProductArn ?? "";
    if (findingId && productArn) {
      try {
        await sechub.send(
          new BatchUpdateFindingsCommand({
            FindingIdentifiers: [{ Id: findingId, ProductArn: productArn }],
            Workflow: { Status: "NOTIFIED" as any },
            Note: { Text: `Patch attempt for ${title}`, UpdatedBy: "sechub-auto-remediation" },
          }),
        );
      } catch {}
    }

    if (!(await isInstanceManaged(instanceId))) {
      await notify(notifyTitle, instanceId, "SKIPPED", `Instance ${instanceId} is not managed by SSM`);
      return { status: "SKIPPED", reason: "not SSM managed" };
    }

    // Ask Bedrock for the patch command
    const trimmed = {
      Title: title,
      Description: finding.Description ?? "",
      Severity: finding.Severity ?? {},
      Resources: finding.Resources ?? [],
      Remediation: finding.Remediation ?? {},
      Vulnerabilities: finding.Vulnerabilities ?? [],
      ProductFields: finding.ProductFields ?? {},
    };

    const decision: Record<string, string> = await callBedrock(
      PROMPT.replace("{{finding}}", JSON.stringify(trimmed, null, 2)),
    );
    console.log(JSON.stringify({ event: "BEDROCK_PATCH_DECISION", instanceId, ...decision }));

    if (decision.action !== "PATCH") {
      await notify(notifyTitle, instanceId, "SKIPPED", decision.reason ?? "Bedrock skipped");
      return { status: "SKIPPED", reason: decision.reason };
    }

    const { Command } = await ssm.send(
      new SendCommandCommand({
        InstanceIds: [instanceId],
        DocumentName: "AWS-RunShellScript",
        Parameters: { commands: [decision.command] },
        TimeoutSeconds: 600,
        Comment: `Auto-patch: ${title}`,
      }),
    );

    const commandId = Command?.CommandId ?? "unknown";
    const cmdUrl = ssmCommandUrl(commandId);
    await notify(
      notifyTitle,
      instanceId,
      "PATCH_STARTED",
      `Patching ${packages} on \`${instanceId}\`\n<${cmdUrl}|View in console>`,
    );

    const result = await waitForCommand(commandId, instanceId);

    if (result.status === "Success") {
      console.log(JSON.stringify({ event: "PATCH_COMPLETE", instanceId, commandId, command: decision.command }));
      await notify(
        notifyTitle,
        instanceId,
        "PATCH_COMPLETE",
        `Patched ${packages} on \`${instanceId}\`\n<${cmdUrl}|View in console>`,
      );
      return { status: "PATCH_COMPLETE", instanceId, commandId };
    } else {
      console.log(JSON.stringify({ event: "PATCH_FAILED", instanceId, commandId, status: result.status }));
      await notify(
        notifyTitle,
        instanceId,
        "PATCH_FAILED",
        `Failed to patch ${packages} on \`${instanceId}\`\nError: ${result.output.slice(0, 500)}\n<${cmdUrl}|View in console>`,
      );
      return { status: "PATCH_FAILED", instanceId, detail: result.status };
    }
  } finally {
    await releaseLock(instanceId);
  }
}

async function acquireLock(instanceId: string): Promise<boolean> {
  try {
    await ddb.send(
      new PutItemCommand({
        TableName: LOCK_TABLE,
        Item: {
          instanceId: { S: instanceId },
          expiresAt: { N: String(Math.floor(Date.now() / 1000) + 300) }, // 5 min TTL
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

async function waitForCommand(
  commandId: string,
  instanceId: string,
  maxWaitMs = 90000,
): Promise<{ status: string; output: string }> {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    await new Promise((r) => setTimeout(r, 5000));
    try {
      const inv = await ssm.send(new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: instanceId }));
      const status = inv.Status ?? "Pending";
      if (["Success", "Failed", "TimedOut", "Cancelled"].includes(status))
        return { status, output: inv.StandardOutputContent ?? inv.StandardErrorContent ?? "" };
    } catch {}
  }
  return { status: "StillRunning", output: "Timed out waiting — check SSM console" };
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
