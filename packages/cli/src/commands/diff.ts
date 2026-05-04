import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Command } from "commander";
import { diffCapabilityGraphs, type CapabilityGraph } from "@mcp-capagate/core";

export function registerDiffCommand(program: Command): void {
  program
    .command("diff")
    .description("Compare a baseline capability graph with a current scan.")
    .requiredOption("--baseline <path>", "baseline JSON graph or baseline record")
    .requiredOption("--current <path>", "current graph JSON")
    .option("-o, --out <path>", "drift report JSON", "reports/drift.json")
    .action(async (options: { baseline: string; current: string; out: string }) => {
      const baseline = unwrapGraph(JSON.parse(await readFile(options.baseline, "utf8")) as unknown);
      const current = unwrapGraph(JSON.parse(await readFile(options.current, "utf8")) as unknown);
      const report = diffCapabilityGraphs(baseline, current);
      await mkdir(dirname(options.out), { recursive: true });
      await writeFile(options.out, `${JSON.stringify(report, null, 2)}\n`, "utf8");
      console.log(`Drift findings: ${report.findings.length}`);
      for (const finding of report.findings) {
        console.log(`[${finding.severity}] ${finding.message}`);
      }
      if (report.should_fail) {
        process.exitCode = 1;
      }
    });
}

function unwrapGraph(value: unknown): CapabilityGraph {
  const maybeRecord = value as { graph?: CapabilityGraph };
  return maybeRecord.graph ?? (value as CapabilityGraph);
}
