import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, compilePolicy, evaluatePolicy, normalizeToolDefinitions } from "../packages/core/src/index.js";

function loadAgentWorkspaceTools(): unknown {
  return JSON.parse(readFileSync(new URL("../examples/agent-workspace-risk/tools.json", import.meta.url), "utf8"));
}

describe("agent workspace risk example", () => {
  it("scans realistic workspace tools and compiles risky policy decisions", () => {
    const tools = normalizeToolDefinitions(loadAgentWorkspaceTools());
    const graph = buildCapabilityGraph(tools, "examples/agent-workspace-risk/tools.json");
    const policy = compilePolicy(graph);

    const nodeFor = (tool: string) => {
      const node = graph.nodes.find((candidate) => candidate.tool === tool);
      if (!node) {
        throw new Error(`Missing graph node for ${tool}`);
      }
      return node;
    };

    const refund = nodeFor("issue_refund");
    expect(refund.capabilities).toContain("financial_action");
    expect(["require_approval", "block"]).toContain(evaluatePolicy(policy, { tool: refund.tool, capabilityNode: refund }).decision);

    const shell = nodeFor("execute_shell");
    expect(shell.risk_level).toBe("critical");
    expect(evaluatePolicy(policy, { tool: shell.tool, capabilityNode: shell }).decision).toBe("block");

    const email = nodeFor("send_email");
    expect(email.capabilities).toContain("send_message");
    expect(email.capabilities).toContain("external_network");
    expect(["require_approval", "block"]).toContain(evaluatePolicy(policy, { tool: email.tool, capabilityNode: email }).decision);
  });
});