import { readFile } from "node:fs/promises";
import { parse as parseYaml } from "yaml";
import type { Command } from "commander";
import { runStdioProxy, type CapabilityGraph, type PolicyDocument } from "@mcp-capagate/core";

export function registerWrapCommand(program: Command): void {
  program
    .command("wrap")
    .description("Run an upstream stdio MCP server behind the MCP CapaGate transparent proxy.")
    .requiredOption("--policy <path>", "policy YAML")
    .option("--scan <path>", "capability graph JSON for runtime attack-chain context")
    .option("--audit <path>", "audit JSONL path", ".capagate/audit.jsonl")
    .option("--session <id>", "session id", "default")
    .option("--interactive", "ask y/N for require_approval decisions", false)
    .allowUnknownOption(true)
    .argument("[upstream...]", "upstream command after --")
    .action(async (upstream: string[], options: { policy: string; scan?: string; audit: string; session: string; interactive: boolean }) => {
      if (!upstream.length) {
        throw new Error("Missing upstream command. Example: capagate wrap --policy capagate.policy.yaml -- npx server");
      }
      const policy = parseYaml(await readFile(options.policy, "utf8")) as PolicyDocument;
      const graph = options.scan ? (JSON.parse(await readFile(options.scan, "utf8")) as CapabilityGraph) : undefined;
      const command = upstream[0];
      const args = upstream.slice(1);
      if (!command) {
        throw new Error("Missing upstream command.");
      }
      const code = await runStdioProxy({
        command,
        args,
        policy,
        graph,
        auditLogPath: options.audit,
        sessionId: options.session,
        interactive: options.interactive
      });
      process.exitCode = code;
    });
}
