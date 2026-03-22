import { build, context } from "esbuild";
import { cpSync } from "fs";

const shared = {
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  outExtension: { ".js": ".mjs" },
  // AWS SDK is available in the Lambda runtime, no need to bundle it
  external: [
    "@aws-sdk/*",
  ],
};

const handlers = [
  { entry: "src/cspm/handler.ts", out: "dist/cspm/handler" },
  { entry: "src/inspector/handler.ts", out: "dist/inspector/handler" },
  { entry: "src/ssm-callback/handler.ts", out: "dist/ssm-callback/handler" },
  { entry: "src/slack/handler.ts", out: "dist/slack/handler" },
];

for (const h of handlers) {
  await build({ ...shared, entryPoints: [h.entry], outfile: `${h.out}.mjs` });
}

// esbuild doesn't handle non-code files, so copy prompts
cpSync("src/cspm/prompts", "dist/cspm/prompts", { recursive: true });
cpSync("src/inspector/prompts", "dist/inspector/prompts", { recursive: true });
