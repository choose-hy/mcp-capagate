import { describe, expect, it } from "vitest";
import { renderBenchmarkMarkdown, runBenchmarkSuite } from "../packages/core/src/index.js";

describe("MCP Tool Risk Benchmark", () => {
  it("runs the tool-risk-suite and computes metrics", async () => {
    const report = await runBenchmarkSuite("benchmarks/tool-risk-suite");
    expect(report.metrics.scenario_count).toBe(14);
    expect(report.metrics.passed_scenarios).toBe(14);
    expect(report.metrics.scenario_pass_rate).toBe(1);
    expect(report.metrics.capability_match_rate).toBeGreaterThanOrEqual(0.95);
    expect(report.metrics.policy_decision_match_rate).toBe(1);
    expect(report.metrics.scanner_finding_match_rate).toBe(1);
  });

  it("renders a markdown benchmark summary", async () => {
    const report = await runBenchmarkSuite("benchmarks/tool-risk-suite");
    const markdown = renderBenchmarkMarkdown(report);
    expect(markdown).toContain("# MCP Tool Risk Benchmark");
    expect(markdown).toContain("safe_read_only");
    expect(markdown).toContain("secret_read_then_external_send");
  });
});
