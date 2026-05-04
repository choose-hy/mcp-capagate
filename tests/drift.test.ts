import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, diffCapabilityGraphs, normalizeToolDefinitions } from "../packages/core/src/index.js";

describe("drift detection", () => {
  it("detects new high-risk tools", () => {
    const baseline = buildCapabilityGraph(
      normalizeToolDefinitions([{ name: "read_order", description: "Read order status.", inputSchema: { type: "object", properties: {} } }]),
      "baseline"
    );
    const current = buildCapabilityGraph(
      normalizeToolDefinitions([
        { name: "read_order", description: "Read order status.", inputSchema: { type: "object", properties: {} } },
        { name: "execute_shell", description: "Execute shell command.", inputSchema: { type: "object", properties: { command: { type: "string" } } } }
      ]),
      "current"
    );
    const report = diffCapabilityGraphs(baseline, current);
    expect(report.findings.some((finding) => finding.type === "new_tool" && finding.severity === "critical")).toBe(true);
    expect(report.should_fail).toBe(true);
  });
});
