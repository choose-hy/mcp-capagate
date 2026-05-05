import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Command } from "commander";
import { createBaseline, unwrapBaselineGraph, verifyBaselineDrift, type DriftFailThreshold } from "@mcp-capagate/core";

export function registerBaselineCommand(program: Command): void {
  const baseline = program.command("baseline").description("Save and verify capability graph baselines for CI drift workflows.");

  baseline
    .command("save")
    .description("Save a capability graph as a baseline record.")
    .requiredOption("--scan <path>", "scan graph JSON")
    .requiredOption("--out <path>", "baseline output path")
    .action(async (options: { scan: string; out: string }) => {
      const graph = unwrapBaselineGraph(JSON.parse(await readFile(options.scan, "utf8")) as unknown);
      const record = createBaseline(graph);
      await mkdir(dirname(options.out), { recursive: true });
      await writeFile(options.out, `${JSON.stringify(record, null, 2)}\n`, "utf8");
      console.log(`Saved baseline ${record.graph_hash} to ${options.out}`);
    });

  baseline
    .command("verify")
    .description("Compare a current scan against a saved baseline and fail on configured drift.")
    .requiredOption("--baseline <path>", "baseline JSON graph or baseline record")
    .requiredOption("--current <path>", "current scan graph JSON")
    .option("--fail-on <severity>", "drift fail threshold: medium, high, critical", "high")
    .option("-o, --out <path>", "drift report JSON", "reports/drift.json")
    .action(async (options: { baseline: string; current: string; failOn: string; out: string }) => {
      const failOn = parseFailOn(options.failOn);
      const report = verifyBaselineDrift(JSON.parse(await readFile(options.baseline, "utf8")) as unknown, JSON.parse(await readFile(options.current, "utf8")) as unknown, failOn);

      await mkdir(dirname(options.out), { recursive: true });
      await writeFile(options.out, `${JSON.stringify(report, null, 2)}\n`, "utf8");

      console.log(`Baseline drift findings: ${report.findings.length}`);
      for (const finding of report.findings) {
        console.log(`[${finding.severity}] ${finding.message}`);
      }
      if (report.should_fail) {
        process.exitCode = 1;
      }
    });
}

function parseFailOn(value: string): DriftFailThreshold {
  if (value === "medium" || value === "high" || value === "critical") {
    return value;
  }
  throw new Error(`Invalid drift fail threshold ${value}. Expected medium, high, or critical.`);
}
