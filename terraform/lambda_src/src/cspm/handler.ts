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
import { findUngroundedParam } from "./grounding.js";

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
const AUTOMATION_ROLE_ARN = process.env.AUTOMATION_ROLE_ARN!;
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
  const results = await Promise.all(
    findings.map((f) =>
      processFinding(f).catch((e) => ({ status: "FAILED", error: e.message ?? String(e) })),
    ),
  );
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

  const workflowStatus = finding.Workflow?.Status ?? "NEW";
  if (workflowStatus !== "NEW") {
    console.log(JSON.stringify({ event: "ALREADY_PROCESSED", controlId, resourceId, findingId, workflowStatus }));
    return { control: controlId, status: "SKIPPED", reason: `already ${workflowStatus}` };
  }

  const result = await askBedrockForRunbook(finding, controlId);
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
  if (result.action === "PENDING") {
    await requestApproval(controlId, resourceId, result.document_name, result.reason, finding);
    return { control: controlId, status: "PENDING_APPROVAL", document: result.document_name };
  }

  const docName = result.document_name;
  const params = result.parameters ?? {};
  params.AutomationAssumeRole = [AUTOMATION_ROLE_ARN];

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

async function askBedrockForRunbook(finding: any, controlId: string) {
  const runbooks = (await getAvailableRunbooks()).filter((name) => !name.includes("Delete"));
  const trimmed = {
    Compliance: finding.Compliance ?? {},
    GeneratorId: finding.GeneratorId ?? "",
    Title: finding.Title ?? "",
    Description: finding.Description ?? "",
    Resources: finding.Resources ?? [],
    Remediation: finding.Remediation ?? {},
  };
  const findingJson = JSON.stringify(trimmed, null, 2);

  const mapping = await getMapping(controlId);
  if (mapping?.status === "REJECTED") return { action: "SKIP", reason: "Mapping rejected" };
  if (mapping?.status === "PENDING") return { action: "SKIP", reason: "Awaiting approval" };

  if (mapping?.status !== "APPROVED") {
    const step1 = await callBedrock(
      PROMPT_PICK.replace("{{runbooks}}", JSON.stringify(runbooks)).replace("{{finding}}", findingJson),
    );
    if (step1.action !== "REMEDIATE") return step1;
    if (!runbooks.includes(step1.document_name))
      return { action: "SKIP", reason: "Bedrock suggested non-existent document" };
    return { action: "PENDING", document_name: step1.document_name, reason: step1.reason };
  }

  const documentName = mapping.document;
  if (!runbooks.includes(documentName)) return { action: "SKIP", reason: `${documentName} is no longer allowed` };

  const docParams = await getDocParameters(documentName);
  if (!docParams) return { action: "SKIP", reason: `Could not fetch params for ${documentName}` };

  const step2 = await callBedrock(
    PROMPT_FILL.replace("{{documentName}}", documentName)
      .replace("{{docParams}}", JSON.stringify(docParams, null, 2))
      .replace("{{finding}}", findingJson),
  );

  if (step2.skip) return { action: "SKIP", reason: step2.reason ?? "Required parameters could not be determined" };

  const parameters = step2.parameters ?? {};
  const ungrounded = findUngroundedParam(parameters, docParams, findingJson);
  if (ungrounded) return { action: "SKIP", reason: `Parameter ${ungrounded} not found in finding` };

  return {
    action: "REMEDIATE",
    document_name: documentName,
    parameters,
    reason: "approved mapping",
  };
}

async function getMapping(controlId: string) {
  const { Item } = await ddb.send(
    new GetItemCommand({ TableName: RUNBOOK_CACHE_TABLE, Key: { pk: { S: `control#${controlId}` } } }),
  );
  if (!Item) return null;
  const expiresAt = Number(Item.expiresAt?.N ?? Infinity);
  if (expiresAt < Date.now() / 1000) return null;
  return { status: Item.status?.S, document: Item.document?.S ?? "" };
}

async function requestApproval(controlId: string, resourceId: string, docName: string, reason: string, finding: any) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await ddb.send(
      new PutItemCommand({
        TableName: RUNBOOK_CACHE_TABLE,
        Item: {
          pk: { S: `control#${controlId}` },
          status: { S: "PENDING" },
          document: { S: docName },
          finding: { S: JSON.stringify(finding) },
          expiresAt: { N: String(now + 7 * 24 * 3600) },
        },
        ConditionExpression: "attribute_not_exists(pk) OR expiresAt < :now",
        ExpressionAttributeValues: { ":now": { N: String(now) } },
      }),
    );
  } catch (e: any) {
    if (e.name === "ConditionalCheckFailedException") return;
    throw e;
  }
  console.log(JSON.stringify({ event: "APPROVAL_REQUESTED", controlId, resourceId, document: docName }));
  await notify(
    controlId,
    resourceId,
    "APPROVAL_REQUESTED",
    finding.ProductFields?.["aws/securityhub/ProductName"] ?? "Security Hub",
    `approval#${controlId}`,
    `finding: <${sechubFindingUrl(finding.Id)}|${finding.Id.split("/").pop()}>\nproposed: \`${docName}\`\nreason: ${reason}`,
    controlId,
  );
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
  approval?: string,
) {
  try {
    await sns.send(
      new PublishCommand({
        TopicArn: SNS_TOPIC_ARN,
        Subject: `[${status}] ${controlId}`,
        Message: JSON.stringify(
          { control: controlId, resource: resourceId, status, product, threadKey, message, approval },
          null,
          2,
        ),
      }),
    );
  } catch (e: any) {
    console.log(JSON.stringify({ event: "NOTIFY_FAILED", controlId, status, error: e.message ?? String(e) }));
  }
}
