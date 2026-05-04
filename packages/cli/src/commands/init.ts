import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import type { Command } from "commander";

const CONFIG = `project:
  name: "Demo MCP Agent"
  owner: "AI Security Team"

inputs:
  tools: "./examples/refund-server/tools.json"

policy:
  defaults:
    unknown_tool: block
    fail_closed: true
  approval:
    interactive: false
  thresholds:
    fail_on: high

runtime:
  mode: shadow
  audit_log: ".capagate/audit.jsonl"
  redact_responses: true

drift:
  enabled: true
  baseline: ".capagate/baseline.json"
  block_on_high_or_critical_change: true

response_scanning:
  redact_secrets: true
  redact_pii: true
  block_external_exfiltration_markers: true
`;

const EMPTY_POLICY = `version: "0.1"
generated_at: "1970-01-01T00:00:00.000Z"
defaults:
  unknown_tool: block
  fail_closed: true
  redact_response: true
rules: []
policy_hash: "bootstrap"
`;

export function registerInitCommand(program: Command): void {
  program
    .command("init")
    .description("Create capagate.yaml, capagate.policy.yaml, .capagate/, reports/, and optional GitHub workflow.")
    .option("--github-action", "create .github/workflows/mcp-capagate.yml", false)
    .option("--force", "overwrite existing config files", false)
    .action(async (options: { githubAction: boolean; force: boolean }) => {
      await mkdir(".capagate", { recursive: true });
      await mkdir("reports", { recursive: true });
      await writeIfAllowed("capagate.yaml", CONFIG, options.force);
      await writeIfAllowed("capagate.policy.yaml", EMPTY_POLICY, options.force);
      if (options.githubAction) {
        await mkdir(".github/workflows", { recursive: true });
        await writeIfAllowed(
          ".github/workflows/mcp-capagate.yml",
          `name: MCP CapaGate
on:
  pull_request:
  push:
jobs:
  capagate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./ 
        with:
          config: capagate.yaml
          fail-on: high
          report-dir: reports
`,
          options.force
        );
      }
      console.log("MCP CapaGate initialized.");
    });
}

async function writeIfAllowed(path: string, content: string, force: boolean): Promise<void> {
  if (existsSync(path) && !force) {
    return;
  }
  await writeFile(path, content, "utf8");
}
