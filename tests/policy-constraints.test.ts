import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, compilePolicy, evaluatePolicy, normalizeToolDefinitions, type PolicyDocument } from "../packages/core/src/index.js";

function graphFor(rawTools: unknown[]) {
  return buildCapabilityGraph(normalizeToolDefinitions(rawTools), "policy-constraints-test");
}

function node(graph: ReturnType<typeof graphFor>, tool: string) {
  const found = graph.nodes.find((candidate) => candidate.tool === tool);
  if (!found) {
    throw new Error(`Missing node for ${tool}`);
  }
  return found;
}

describe("constraint-aware policy DSL", () => {
  it("allows read_file under safe prefixes and blocks traversal outside them", () => {
    const graph = graphFor([
      {
        name: "read_file",
        description: "Read a file by workspace path.",
        inputSchema: { type: "object", properties: { path: { type: "string" } } }
      }
    ]);
    const policy = compilePolicy(graph);
    const readFile = node(graph, "read_file");

    expect(evaluatePolicy(policy, { tool: "read_file", capabilityNode: readFile, arguments: { path: "docs/runbook.md" } }).decision).toBe("allow");

    const blocked = evaluatePolicy(policy, { tool: "read_file", capabilityNode: readFile, arguments: { path: "../private.env" } });
    expect(blocked.decision).toBe("block");
    expect(blocked.constraint_findings?.[0]?.matched_constraint).toBe("path_prefixes");
  });

  it("enforces refund amount and confirmation constraints", () => {
    const graph = graphFor([
      {
        name: "issue_refund",
        description: "Issue a billing refund after confirmation.",
        inputSchema: { type: "object", properties: { amount: { type: "number" }, confirmed: { type: "boolean" } } }
      }
    ]);
    const policy = compilePolicy(graph);
    const refund = node(graph, "issue_refund");

    expect(evaluatePolicy(policy, { tool: "issue_refund", capabilityNode: refund, arguments: { amount: 50, confirmed: true } }).decision).toBe("require_approval");
    expect(evaluatePolicy(policy, { tool: "issue_refund", capabilityNode: refund, arguments: { amount: 150, confirmed: true } }).decision).toBe("block");
    expect(evaluatePolicy(policy, { tool: "issue_refund", capabilityNode: refund, arguments: { amount: 50 } }).decision).toBe("block");
  });

  it("enforces email domain allowlists", () => {
    const policy: PolicyDocument = {
      version: "0.1",
      generated_at: "2026-01-01T00:00:00.000Z",
      defaults: { unknown_tool: "block", fail_closed: true, redact_response: true },
      rules: [
        {
          id: "test.company_email_only",
          match: { tool: "send_email" },
          decision: "allow",
          reason: "Allow company email only.",
          constraints: { allowed_domains: ["company.com"], required_argument_paths: ["to"] },
          controls: ["destination_allowlist"],
          priority: 100
        }
      ],
      policy_hash: "test"
    };

    expect(evaluatePolicy(policy, { tool: "send_email", arguments: { to: "security@company.com" } }).decision).toBe("allow");
    expect(evaluatePolicy(policy, { tool: "send_email", arguments: { to: "person@example.com" } }).decision).toBe("block");
  });

  it("blocks webhook hosts when no host is allowlisted", () => {
    const graph = graphFor([
      {
        name: "post_webhook",
        description: "Post a JSON payload to a webhook URL.",
        inputSchema: { type: "object", properties: { webhook_url: { type: "string" } } }
      }
    ]);
    const policy = compilePolicy(graph);
    const webhook = node(graph, "post_webhook");

    const decision = evaluatePolicy(policy, { tool: "post_webhook", capabilityNode: webhook, arguments: { webhook_url: "https://hooks.example.net/agent" } });
    expect(decision.decision).toBe("block");
    expect(decision.constraint_findings?.[0]?.matched_constraint).toBe("allowed_domains");
  });

  it("supports nested argument paths and blocked argument patterns", () => {
    const policy: PolicyDocument = {
      version: "0.1",
      generated_at: "2026-01-01T00:00:00.000Z",
      defaults: { unknown_tool: "block", fail_closed: true, redact_response: true },
      rules: [
        {
          id: "test.nested_constraints",
          match: { tool: "diagnostic_note" },
          decision: "allow",
          reason: "Allow safe diagnostic notes.",
          constraints: {
            required_boolean_flags: ["approval.confirmed"],
            blocked_argument_patterns: [{ path: "metadata.command", pattern: "rm\\s+-rf", reason: "Dangerous command pattern." }]
          },
          controls: ["constraint_review"],
          priority: 100
        }
      ],
      policy_hash: "test"
    };

    expect(
      evaluatePolicy(policy, {
        tool: "diagnostic_note",
        arguments: { approval: { confirmed: true }, metadata: { command: "echo safe" } }
      }).decision
    ).toBe("allow");

    const blocked = evaluatePolicy(policy, {
      tool: "diagnostic_note",
      arguments: { approval: { confirmed: true }, metadata: { command: "rm -rf /tmp/example" } }
    });
    expect(blocked.decision).toBe("block");
    expect(blocked.constraint_findings?.[0]?.argument_path).toBe("metadata.command");
  });
});