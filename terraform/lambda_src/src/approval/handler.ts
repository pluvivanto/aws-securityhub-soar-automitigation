import { createHmac, timingSafeEqual } from "node:crypto";
import { DynamoDBClient, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { InvokeCommand, LambdaClient } from "@aws-sdk/client-lambda";

const ddb = new DynamoDBClient({});
const lambda = new LambdaClient({});

const SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET!;
const RUNBOOK_CACHE_TABLE = process.env.RUNBOOK_CACHE_TABLE!;
const CSPM_FUNCTION_NAME = process.env.CSPM_FUNCTION_NAME!;

export async function handler(event: any) {
  const raw = event.isBase64Encoded ? Buffer.from(event.body ?? "", "base64").toString() : (event.body ?? "");
  if (!verifySlackSignature(event.headers ?? {}, raw)) return { statusCode: 401 };

  const payload = JSON.parse(new URLSearchParams(raw).get("payload") ?? "{}");
  const action = payload.actions?.[0];
  if (!action) return { statusCode: 200 };

  const approved = action.action_id === "approve";
  const controlId: string = action.value;
  const user = payload.user?.username ?? payload.user?.id ?? "unknown";

  let text: string;
  try {
    const { Attributes: old } = await ddb.send(
      new UpdateItemCommand({
        TableName: RUNBOOK_CACHE_TABLE,
        Key: { pk: { S: `control#${controlId}` } },
        UpdateExpression: "SET #s = :s, decidedBy = :u, decidedAt = :t REMOVE finding",
        ConditionExpression: "#s = :pending",
        ExpressionAttributeNames: { "#s": "status" },
        ExpressionAttributeValues: {
          ":s": { S: approved ? "APPROVED" : "REJECTED" },
          ":u": { S: user },
          ":t": { N: String(Math.floor(Date.now() / 1000)) },
          ":pending": { S: "PENDING" },
        },
        ReturnValues: "ALL_OLD",
      }),
    );
    if (approved && old?.finding?.S) {
      await lambda.send(
        new InvokeCommand({
          FunctionName: CSPM_FUNCTION_NAME,
          InvocationType: "Event",
          Payload: JSON.stringify({ finding: JSON.parse(old.finding.S) }),
        }),
      );
    }
    text = `${approved ? ":white_check_mark: Approved" : ":no_entry_sign: Rejected"} *${controlId}* → \`${old?.document?.S}\` by @${user}`;
  } catch (e: any) {
    if (e.name !== "ConditionalCheckFailedException") throw e;
    text = `*${controlId}* was already decided`;
  }

  console.log(JSON.stringify({ event: "APPROVAL_DECISION", controlId, approved, user }));
  if (payload.response_url) {
    await fetch(payload.response_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ replace_original: true, text }),
    });
  }
  return { statusCode: 200 };
}

function verifySlackSignature(headers: Record<string, string>, raw: string) {
  const ts = headers["x-slack-request-timestamp"];
  const sig = headers["x-slack-signature"] ?? "";
  if (!ts || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const expected = `v0=${createHmac("sha256", SIGNING_SECRET).update(`v0:${ts}:${raw}`).digest("hex")}`;
  return sig.length === expected.length && timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}
