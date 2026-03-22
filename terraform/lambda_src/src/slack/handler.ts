import { request } from "node:https";
import type { SNSEvent } from "aws-lambda";

const WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL!;

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

export async function handler(event: SNSEvent) {
  for (const record of event.Records) {
    await postToSlack(JSON.parse(record.Sns.Message));
  }
}

async function postToSlack(msg: any) {
  const status = msg.status ?? "UNKNOWN";
  const emoji = STATUS_EMOJI[status] ?? ":question:";

  const payload = {
    blocks: [
      {
        type: "section",
        text: { type: "mrkdwn", text: `${emoji} *${msg.control ?? "?"}*` },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Status:*\n${status}` },
          { type: "mrkdwn", text: `*Resource:*\n\`${msg.resource ?? "?"}\`` },
        ],
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*Detail:*\n${(msg.message ?? "").slice(0, 2500)}` },
      },
    ],
  };

  return new Promise<void>((resolve, reject) => {
    const url = new URL(WEBHOOK_URL);
    const req = request(
      { hostname: url.hostname, path: url.pathname, method: "POST", headers: { "Content-Type": "application/json" } },
      (res) => {
        res.resume();
        res.on("end", resolve);
      },
    );
    req.on("error", reject);
    req.end(JSON.stringify(payload));
  });
}
