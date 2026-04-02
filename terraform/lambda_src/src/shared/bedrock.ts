import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";

const bedrock = new BedrockRuntimeClient({});
const MODEL_ID = process.env.BEDROCK_MODEL_ID!;
const REGION = process.env.AWS_REGION ?? "us-east-1";

export async function callBedrock(prompt: string, maxTokens = 1024, attempt = 0): Promise<any> {
  try {
    const res = await bedrock.send(
      new InvokeModelCommand({
        modelId: MODEL_ID,
        contentType: "application/json",
        accept: "application/json",
        body: JSON.stringify({
          anthropic_version: "bedrock-2023-05-31",
          max_tokens: maxTokens,
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
  } catch (e: any) {
    if (e.name === "ThrottlingException" && attempt < 3) {
      await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
      return callBedrock(prompt, maxTokens, attempt + 1);
    }
    throw e;
  }
}

export function sechubFindingUrl(findingId: string) {
  return `https://${REGION}.console.aws.amazon.com/securityhub/home?region=${REGION}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A${encodeURIComponent(encodeURIComponent(findingId))}`;
}
