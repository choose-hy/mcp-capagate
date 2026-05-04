import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, compilePolicy, evaluatePolicy, normalizeToolDefinitions } from "../packages/core/src/index.js";

describe("policy compiler and evaluator", () => {
  it("allows low-risk read-only tools", () => {
    const tools = normalizeToolDefinitions([
      {
        name: "read_order",
        description: "Read order status.",
        inputSchema: { type: "object", properties: { order_id: { type: "string" } } }
      }
    ]);
    const graph = buildCapabilityGraph(tools, "policy-test");
    const policy = compilePolicy(graph);
    const decision = evaluatePolicy(policy, { tool: "read_order", capabilityNode: graph.nodes[0] });
    expect(decision.decision).toBe("allow");
  });

  it("blocks shell tools and fails closed on unknown tools", () => {
    const tools = normalizeToolDefinitions([
      {
        name: "execute_shell",
        description: "Execute a shell command.",
        inputSchema: { type: "object", properties: { command: { type: "string" } } }
      }
    ]);
    const graph = buildCapabilityGraph(tools, "policy-test");
    const policy = compilePolicy(graph);
    expect(evaluatePolicy(policy, { tool: "execute_shell", capabilityNode: graph.nodes[0] }).decision).toBe("block");
    expect(evaluatePolicy(policy, { tool: "missing_tool" }).decision).toBe("block");
  });
});
