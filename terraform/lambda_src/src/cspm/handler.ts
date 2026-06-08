import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { BatchUpdateFindingsCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import {
  DescribeDocumentCommand,
  paginateListDocuments,
  SSMClient,
  StartAutomationExecutionCommand,
} from "@aws-sdk/client-ssm";
import { callBedrock, sechubFindingUrl } from "../shared/bedrock.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const loadPrompt = (name: string) => readFileSync(join(__dirname, "prompts", name), "utf-8");

const PROMPT_PICK = loadPrompt("pick-runbook.txt");
const PROMPT_FILL = loadPrompt("fill-params.txt");

const ssm = new SSMClient({});
const sechub = new SecurityHubClient({});
const sns = new SNSClient({});
const ddb = new DynamoDBClient({});

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN!;
const ENABLED_CONTROLS: string[] = JSON.parse(process.env.ENABLED_CONTROLS ?? '["*"]');
const LAMBDA_ROLE_ARN = process.env.LAMBDA_ROLE_ARN!;
const REGION = process.env.AWS_REGION ?? "us-east-1";
const RUNBOOK_CACHE_TABLE = process.env.RUNBOOK_CACHE_TABLE!;

function ssmAutomationUrl(executionId: string) {
  return `https://${REGION}.console.aws.amazon.com/systems-manager/automation/execution/${executionId}?region=${REGION}`;
}

let runbookMemCache: string[] | null = null;

export async function handler(event: any) {
  const findings: any[] = [];
  if (event.Records) {
    for (const record of event.Records) {
      const body = JSON.parse(record.body);
      findings.push(...(body.detail?.findings ?? []));
    }
  } else if (event.detail?.findings) {
    findings.push(...event.detail.findings);
  } else if (event.finding) {
    findings.push(event.finding);
  }
  const results = await Promise.all(findings.map(processFinding));
  return { processed: results.length, results };
}

async function processFinding(finding: any) {
  const controlId = extractControlId(finding);
  const findingId = finding.Id ?? "unknown";
  const productArn = finding.ProductArn ?? "";
  const resourceId = finding.Resources?.[0]?.Id ?? "unknown";

  console.log(
    JSON.stringify({
      event: "FINDING_RECEIVED",
      controlId,
      resourceId,
      source: finding.ProductFields?.["aws/securityhub/ProductName"] ?? productArn,
      findingTitle: finding.Title ?? "",
      severity: finding.Severity?.Label ?? "UNKNOWN",
    }),
  );

  if (!isControlEnabled(controlId)) return { control: controlId, status: "SKIPPED", reason: "not enabled" };

  const result = await askBedrockForRunbook(finding);
  console.log(
    JSON.stringify({
      event: "BEDROCK_DECISION",
      controlId,
      resourceId,
      action: result.action,
      document: result.document_name ?? null,
      parameters: result.parameters ?? null,
      reason: result.reason ?? null,
    }),
  );

  if (result.action === "SKIP") return { control: controlId, status: "SKIPPED", reason: result.reason };

  const docName = result.document_name;
  const params = result.parameters ?? {};
  params.AutomationAssumeRole = [LAMBDA_ROLE_ARN];

  let execId: string | undefined;
  try {
    const resp = await ssm.send(
      new StartAutomationExecutionCommand({
        DocumentName: docName,
        Parameters: params,
      }),
    );
    execId = resp.AutomationExecutionId;
  } catch (err: any) {
    console.log(JSON.stringify({ event: "SSM_ERROR", controlId, resourceId, document: docName, error: err.message }));
    return { control: controlId, status: "FAILED", document: docName, error: err.message };
  }

  const product = finding.ProductFields?.["aws/securityhub/ProductName"] ?? "Security Hub";
  const shortId = findingId.split("/").pop() ?? findingId;
  const msg = `${execId} | ${docName}`;
  console.log(JSON.stringify({ event: "SSM_STARTED", controlId, resourceId, document: docName, executionId: execId }));
  await updateFinding(findingId, productArn, "NOTIFIED", msg);
  await notify(
    controlId,
    resourceId,
    "STARTED",
    product,
    execId!,
    `finding: <${sechubFindingUrl(findingId)}|${shortId}>\n${docName}\nexecution: ${execId}\n<${ssmAutomationUrl(execId!)}|View in console>`,
  );
  return { control: controlId, status: "STARTED", document: docName, execution_id: execId };
}

async function askBedrockForRunbook(finding: any) {
  const runbooks = await getAvailableRunbooks();
  const trimmed = {
    Compliance: finding.Compliance ?? {},
    GeneratorId: finding.GeneratorId ?? "",
    Title: finding.Title ?? "",
    Description: finding.Description ?? "",
    Resources: finding.Resources ?? [],
    Remediation: finding.Remediation ?? {},
  };
  const findingJson = JSON.stringify(trimmed, null, 2);

  const step1 = await callBedrock(
    PROMPT_PICK.replace("{{runbooks}}", JSON.stringify(runbooks)).replace("{{finding}}", findingJson),
  );

  if (step1.action !== "REMEDIATE") return step1;
  if (!runbooks.includes(step1.document_name))
    return { action: "SKIP", reason: "Bedrock suggested non-existent document" };

  const docParams = await getDocParameters(step1.document_name);
  if (!docParams) return { action: "SKIP", reason: `Could not fetch params for ${step1.document_name}` };

  const step2 = await callBedrock(
    PROMPT_FILL.replace("{{documentName}}", step1.document_name)
      .replace("{{docParams}}", JSON.stringify(docParams, null, 2))
      .replace("{{finding}}", findingJson),
  );

  if (step2.skip) return { action: "SKIP", reason: step2.reason ?? "Required parameters could not be determined" };

  return {
    action: "REMEDIATE",
    document_name: step1.document_name,
    parameters: step2.parameters ?? {},
    reason: step1.reason,
  };
}

async function getAvailableRunbooks(): Promise<string[]> {
  if (runbookMemCache) return runbookMemCache;

  const { Item } = await ddb.send(
    new GetItemCommand({ TableName: RUNBOOK_CACHE_TABLE, Key: { pk: { S: "runbooks" } } }),
  );
  if (Item?.names?.S) {
    runbookMemCache = JSON.parse(Item.names.S);
    return runbookMemCache!;
  }

  const prefixes = ["AWSConfigRemediation-", "AWS-Disable", "AWS-Enable", "AWS-Close", "AWS-Configure"];
  const names: string[] = [];
  for await (const page of paginateListDocuments(
    { client: ssm },
    {
      Filters: [
        { Key: "Owner", Values: ["Amazon"] },
        { Key: "DocumentType", Values: ["Automation"] },
      ],
    },
  )) {
    for (const doc of page.DocumentIdentifiers ?? [])
      if (doc.Name && prefixes.some((p) => doc.Name!.startsWith(p))) names.push(doc.Name);
  }
  names.sort();

  await ddb.send(
    new PutItemCommand({
      TableName: RUNBOOK_CACHE_TABLE,
      Item: {
        pk: { S: "runbooks" },
        names: { S: JSON.stringify(names) },
        expiresAt: { N: String(Math.floor(Date.now() / 1000) + 6 * 3600) },
      },
    }),
  );

  runbookMemCache = names;
  return runbookMemCache;
}

async function getDocParameters(docName: string) {
  try {
    const { Document: doc } = await ssm.send(new DescribeDocumentCommand({ Name: docName }));
    return (doc?.Parameters ?? []).map((p) => ({
      name: p.Name,
      type: p.Type ?? "String",
      description: p.Description ?? "",
      default: p.DefaultValue ?? "",
      required: !p.DefaultValue && p.Name !== "AutomationAssumeRole",
    }));
  } catch {
    return null;
  }
}

function extractControlId(finding: any): string {
  const id = finding.Compliance?.SecurityControlId;
  if (id) return id;
  const gen: string = finding.GeneratorId ?? "";
  return gen.includes("/") ? gen.split("/").pop()! : gen;
}

function isControlEnabled(id: string): boolean {
  return ENABLED_CONTROLS.includes("*") || ENABLED_CONTROLS.includes(id);
}

async function updateFinding(findingId: string, productArn: string, status: string, note: string) {
  try {
    await sechub.send(
      new BatchUpdateFindingsCommand({
        FindingIdentifiers: [{ Id: findingId, ProductArn: productArn }],
        Workflow: { Status: status as any },
        Note: { Text: note.slice(0, 512), UpdatedBy: "sechub-auto-remediation" },
      }),
    );
  } catch (e: any) {
    console.log(JSON.stringify({ event: "UPDATE_FINDING_FAILED", findingId, status, error: e.message ?? String(e) }));
  }
}

async function notify(
  controlId: string,
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
        Subject: `[${status}] ${controlId}`,
        Message: JSON.stringify(
          { control: controlId, resource: resourceId, status, product, threadKey, message },
          null,
          2,
        ),
      }),
    );
  } catch (e: any) {
    console.log(JSON.stringify({ event: "NOTIFY_FAILED", controlId, status, error: e.message ?? String(e) }));
  }
}
