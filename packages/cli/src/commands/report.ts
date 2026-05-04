import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Command } from "commander";
import {
  generateHtmlReport,
  generateMarkdownReport,
  generateSarifReport,
  readAuditReceipts,
  type CapabilityGraph,
  type DriftReport,
  type PolicyDocument
} from "@mcp-capagate/core";

export function registerReportCommand(program: Command): void {
  program
    .command("report")
    .description("Generate Markdown, static HTML, and optional SARIF reports.")
    .requiredOption("--scan <path>", "capability graph JSON")
    .option("--policy <path>", "policy YAML")
    .option("--audit <path>", "audit JSONL", ".capagate/audit.jsonl")
    .option("--drift <path>", "drift report JSON")
    .option("--html <path>", "HTML report output", "reports/index.html")
    .option("--markdown <path>", "Markdown report output", "reports/summary.md")
    .option("--sarif <path>", "SARIF output")
    .action(async (options: { scan: string; policy?: string; audit: string; drift?: string; html: string; markdown: string; sarif?: string }) => {
      const graph = JSON.parse(await readFile(options.scan, "utf8")) as CapabilityGraph;
      const policy = options.policy ? (parseYaml(await readFile(options.policy, "utf8")) as PolicyDocument) : undefined;
      const audit = readAuditReceipts(options.audit);
      const drift = options.drift ? (JSON.parse(await readFile(options.drift, "utf8")) as DriftReport) : undefined;
      await writeText(options.markdown, generateMarkdownReport({ graph, policy, audit, drift }));
      await writeText(options.html, generateHtmlReport({ graph, policy, audit, drift }));
      if (options.sarif) {
        await writeText(options.sarif, generateSarifReport(graph));
      }
      console.log(`Reports written to ${options.markdown} and ${options.html}`);
    });
}

async function writeText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, value, "utf8");
}
