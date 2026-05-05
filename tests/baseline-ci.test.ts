import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, createBaseline, normalizeToolDefinitions, unwrapBaselineGraph, verifyBaselineDrift } from "../packages/core/src/index.js";

function graphFor(tools: Array<{ name: string; description: string }>) {
  return buildCapabilityGraph(
    normalizeToolDefinitions(
      tools.map((tool) => ({
        ...tool,
        inputSchema: { type: "object", properties: {} }
      }))
    ),
    "baseline-test"
  );
}

describe("baseline CI workflow", () => {
  it("saves and loads baseline records", () => {
    const graph = graphFor([{ name: "read_order", description: "Read order status." }]);
    const record = createBaseline(graph);
    const loaded = unwrapBaselineGraph(JSON.parse(JSON.stringify(record)) as unknown);
    expect(record.graph_hash).toBe(graph.graph_hash);
    expect(loaded.graph_hash).toBe(graph.graph_hash);
  });

  it("passes verification with the same graph", () => {
    const graph = graphFor([{ name: "read_order", description: "Read order status." }]);
    const report = verifyBaselineDrift(createBaseline(graph), graph, "high");
    expect(report.findings).toHaveLength(0);
    expect(report.should_fail).toBe(false);
  });

  it("fails verification on critical risk increase", () => {
    const baseline = graphFor([{ name: "read_order", description: "Read order status." }]);
    const current = graphFor([
      { name: "read_order", description: "Read order status." },
      { name: "execute_shell", description: "Execute shell command." }
    ]);
    const report = verifyBaselineDrift(createBaseline(baseline), current, "high");
    expect(report.findings.some((finding) => finding.type === "new_tool" && finding.severity === "critical")).toBe(true);
    expect(report.should_fail).toBe(true);
  });

  it("exposes baseline inputs in the composite action", () => {
    const action = readFileSync("action.yml", "utf8");
    expect(action).toContain("baseline:");
    expect(action).toContain("fail-on-drift:");
    expect(action).toContain("baseline verify");
  });
});
