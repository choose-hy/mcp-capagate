import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Command } from "commander";
import { renderBenchmarkMarkdown, runBenchmarkSuite } from "@mcp-capagate/core";

export function registerBenchmarkCommand(program: Command): void {
  program
    .command("benchmark")
    .description("Run the MCP Tool Risk Benchmark suite.")
    .requiredOption("--suite <path>", "benchmark suite directory")
    .option("--out <path>", "benchmark JSON output", "reports/benchmark.json")
    .option("--markdown <path>", "benchmark Markdown output", "reports/benchmark.md")
    .action(async (options: { suite: string; out: string; markdown: string }) => {
      const report = await runBenchmarkSuite(options.suite);
      await writeText(options.out, `${JSON.stringify(report, null, 2)}\n`);
      await writeText(options.markdown, renderBenchmarkMarkdown(report));
      console.log(
        `MCP Tool Risk Benchmark: ${report.metrics.passed_scenarios}/${report.metrics.scenario_count} scenarios passed, ` +
          `capability match ${percent(report.metrics.capability_match_rate)}, policy match ${percent(report.metrics.policy_decision_match_rate)}, ` +
          `scanner match ${percent(report.metrics.scanner_finding_match_rate)}.`
      );
      if (report.metrics.passed_scenarios !== report.metrics.scenario_count) {
        process.exitCode = 1;
      }
    });
}

async function writeText(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content, "utf8");
}

function percent(value: number): string {
  return `${Math.round(value * 1000) / 10}%`;
}
