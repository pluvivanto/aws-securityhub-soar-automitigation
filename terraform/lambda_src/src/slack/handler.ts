import { request } from "node:https";
import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import type { SQSEvent } from "aws-lambda";

const BOT_TOKEN = process.env.SLACK_BOT_TOKEN!;
const CHANNEL_ID = process.env.SLACK_CHANNEL_ID!;
const LOCK_TABLE = process.env.LOCK_TABLE!;

const ddb = new DynamoDBClient({});

const STATUS_EMOJI: Record<string, string> = {
  STARTED: ":arrow_forward:",
  FAILED: ":x:",
  SKIPPED: ":fast_forward:",
  PATCH_STARTED: ":wrench:",
  PATCH_COMPLETE: ":white_check_mark:",
  PATCH_FAILED: ":x:",
  REMEDIATION_COMPLETE: ":white_check_mark:",
  REMEDIATION_FAILED: ":x:",
  REMEDIATION_TIMED_OUT: ":hourglass:",
  REMEDIATION_CANCELLED: ":no_entry_sign:",
};

const START_STATUSES = new Set(["STARTED", "PATCH_STARTED"]);
const REPLY_STATUSES = new Set([
  "PATCH_COMPLETE",
  "PATCH_FAILED",
  "REMEDIATION_COMPLETE",
  "REMEDIATION_FAILED",
  "REMEDIATION_TIMED_OUT",
  "REMEDIATION_CANCELLED",
]);
const REACTIONS: Record<string, string> = {
  PATCH_COMPLETE: "thumbsup",
  REMEDIATION_COMPLETE: "thumbsup",
  PATCH_FAILED: "x",
  REMEDIATION_FAILED: "x",
  REMEDIATION_TIMED_OUT: "x",
  REMEDIATION_CANCELLED: "x",
};

export async function handler(event: SQSEvent) {
  for (const record of event.Records) {
    const sns = JSON.parse(record.body);
    await postToSlack(JSON.parse(sns.Message));
  }
}

async function postToSlack(msg: any) {
  const status = msg.status ?? "UNKNOWN";
  const emoji = STATUS_EMOJI[status] ?? ":question:";
  const threadKey = msg.threadKey as string | undefined;

  const fullDetail = msg.message ?? "";
  const detailChunks = splitAtNewlines(fullDetail, 2900);

  const blocks = [
    {
      type: "section",
      text: { type: "mrkdwn", text: `${emoji} *${msg.control ?? "?"}*` },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Status:*\n${status}` },
        { type: "mrkdwn", text: `*Resource:*\n\`${msg.resource ?? "?"}\`` },
        ...(msg.product ? [{ type: "mrkdwn", text: `*Product:*\n${msg.product}` }] : []),
      ],
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `*Detail:*\n${detailChunks[0] ?? ""}` },
    },
  ];

  let thread_ts: string | undefined;
  if (threadKey && REPLY_STATUSES.has(status)) {
    thread_ts = await getThreadTs(threadKey);
    console.log(JSON.stringify({ event: "THREAD_LOOKUP", threadKey, found: !!thread_ts, status }));
  }

  const payload: Record<string, any> = { channel: CHANNEL_ID, blocks };
  if (thread_ts) payload.thread_ts = thread_ts;

  const ts = await callSlackPostMessage(payload);

  if (threadKey && ts && START_STATUSES.has(status)) {
    await storeThreadTs(threadKey, ts);
  }

  if (thread_ts && REACTIONS[status]) {
    await addReaction(thread_ts, REACTIONS[status]);
  }

  if (detailChunks.length > 1 && ts) {
    const replyTs = thread_ts ?? ts;
    for (const chunk of detailChunks.slice(1)) {
      await callSlackPostMessage({
        channel: CHANNEL_ID,
        thread_ts: replyTs,
        blocks: [{ type: "section", text: { type: "mrkdwn", text: chunk } }],
      });
    }
  }
}

function splitAtNewlines(text: string, maxLen: number): string[] {
  const chunks: string[] = [];
  let current = "";
  for (const line of text.split("\n")) {
    const next = current ? `${current}\n${line}` : line;
    if (next.length > maxLen && current) {
      chunks.push(current);
      current = line;
    } else {
      current = next;
    }
  }
  if (current) chunks.push(current);
  return chunks;
}

async function callSlackApi(path: string, payload: Record<string, any>, attempt = 0): Promise<any> {
  return new Promise((resolve) => {
    const body = JSON.stringify(payload);
    const req = request(
      {
        hostname: "slack.com",
        path: `/api/${path}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${BOT_TOKEN}`,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", async () => {
          if (res.statusCode === 429 && attempt < 3) {
            const retryAfter = Number(res.headers["retry-after"] ?? 1);
            await new Promise((r) => setTimeout(r, retryAfter * 1000));
            resolve(callSlackApi(path, payload, attempt + 1));
            return;
          }
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(undefined);
          }
        });
      },
    );
    req.on("error", () => resolve(undefined));
    req.end(body);
  });
}

async function callSlackPostMessage(payload: Record<string, any>): Promise<string | undefined> {
  const res = await callSlackApi("chat.postMessage", payload);
  return res?.ts;
}

async function addReaction(ts: string, emoji: string) {
  const res = await callSlackApi("reactions.add", { channel: CHANNEL_ID, timestamp: ts, name: emoji });
  console.log(JSON.stringify({ event: "REACTION_RESULT", emoji, ok: res?.ok, error: res?.error }));
}

async function storeThreadTs(threadKey: string, ts: string) {
  try {
    await ddb.send(
      new PutItemCommand({
        TableName: LOCK_TABLE,
        Item: {
          instanceId: { S: `slack#${threadKey}` },
          ts: { S: ts },
          expiresAt: { N: String(Math.floor(Date.now() / 1000) + 86400) },
        },
      }),
    );
  } catch {}
}

async function getThreadTs(threadKey: string): Promise<string | undefined> {
  try {
    const { Item } = await ddb.send(
      new GetItemCommand({
        TableName: LOCK_TABLE,
        Key: { instanceId: { S: `slack#${threadKey}` } },
      }),
    );
    return Item?.ts?.S;
  } catch {
    return undefined;
  }
}
