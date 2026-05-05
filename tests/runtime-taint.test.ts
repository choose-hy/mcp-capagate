import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, handleJsonRpcLine, normalizeToolDefinitions, TaintTracker, type PolicyDocument } from "../packages/core/src/index.js";

function toolLine(id: string, name: string, args: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
}

function runtimeGraph() {
  const tools = normalizeToolDefinitions([
    {
      name: "read_customer_profile",
      description: "Read private customer profile email and support history.",
      inputSchema: { type: "object", properties: { customer_id: { type: "string" } } }
    },
    {
      name: "send_email",
      description: "Send an email to an external recipient.",
      inputSchema: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } } }
    },
    {
      name: "read_file",
      description: "Read a file by workspace path.",
      inputSchema: { type: "object", properties: { path: { type: "string" } } }
    }
  ]);
  return buildCapabilityGraph(tools, "runtime-taint-test");
}

function allowRuntimePolicy(): PolicyDocument {
  return {
    version: "0.1",
    generated_at: "2026-01-01T00:00:00.000Z",
    defaults: { unknown_tool: "block", fail_closed: true, redact_response: true },
    rules: [
      { id: "allow.read_customer_profile", match: { tool: "read_customer_profile" }, decision: "allow", reason: "test allow", controls: [], priority: 100 },
      { id: "allow.send_email", match: { tool: "send_email" }, decision: "allow", reason: "test allow", controls: [], priority: 100 },
      { id: "allow.read_file", match: { tool: "read_file" }, decision: "allow", reason: "test allow", controls: [], priority: 100 }
    ],
    policy_hash: "runtime-test"
  };
}

describe("runtime taint tracking and modes", () => {
  it("blocks sensitive read followed by send_email in enforce mode", async () => {
    const graph = runtimeGraph();
    const policy = allowRuntimePolicy();
    const taintTracker = new TaintTracker();

    const read = await handleJsonRpcLine(toolLine("read", "read_customer_profile", { customer_id: "cus_demo" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "enforce-session",
      runtimeMode: "enforce"
    });
    expect(read.action).toBe("forward");

    const send = await handleJsonRpcLine(toolLine("send", "send_email", { to: "ops@example.test", body: "hello" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "enforce-session",
      runtimeMode: "enforce"
    });
    expect(send.action).toBe("respond");
    expect(send.decision?.decision).toBe("block");
    expect(send.decision?.attack_chain_findings?.[0]?.message).toContain("tainted session data");
  });

  it("forwards sensitive send_email in shadow mode and records would_block", async () => {
    const graph = runtimeGraph();
    const policy = allowRuntimePolicy();
    const taintTracker = new TaintTracker();

    await handleJsonRpcLine(toolLine("read", "read_customer_profile", { customer_id: "cus_demo" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "shadow-session",
      runtimeMode: "enforce"
    });

    const send = await handleJsonRpcLine(toolLine("send", "send_email", { to: "ops@example.test", body: "hello" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "shadow-session",
      runtimeMode: "shadow"
    });
    expect(send.action).toBe("forward");
    expect(send.decision?.decision).toBe("allow");
    expect(send.decision?.would_have_decision).toBe("block");
    expect(send.receipt?.would_have_decision).toBe("block");
  });

  it("taints read_file .env but not normal docs reads", async () => {
    const graph = runtimeGraph();
    const policy = allowRuntimePolicy();
    const taintTracker = new TaintTracker();

    const envRead = await handleJsonRpcLine(toolLine("env", "read_file", { path: ".env" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "path-session",
      runtimeMode: "enforce"
    });
    expect(envRead.receipt?.runtime_mode).toBe("enforce");
    expect(envRead.receipt?.taint_labels).toContain("secret_read");
    expect(envRead.receipt?.taint_labels).toContain("filesystem_sensitive_read");

    const cleanTracker = new TaintTracker();
    const docsRead = await handleJsonRpcLine(toolLine("docs", "read_file", { path: "docs/readme.md" }), {
      policy,
      graph,
      taintTracker: cleanTracker,
      sessionId: "docs-session",
      runtimeMode: "enforce"
    });
    expect(docsRead.receipt?.taint_labels).toEqual([]);
    expect(cleanTracker.getTaintLabels("docs-session")).toEqual([]);
  });

  it("taints a session when a tool response contains a secret", async () => {
    const graph = runtimeGraph();
    const policy = allowRuntimePolicy();
    const taintTracker = new TaintTracker();
    taintTracker.recordResponseLine({ session_id: "response-session", tool: "read_file", line: '{"key":"sk-abcdefghijklmnopqrstuvwxyz"}' });

    const send = await handleJsonRpcLine(toolLine("send", "send_email", { to: "ops@example.test", body: "hello" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "response-session",
      runtimeMode: "enforce"
    });
    expect(send.decision?.decision).toBe("block");
    expect(send.decision?.taint_labels).toContain("secret_read");
  });

  it("audit-only never blocks but records attack-chain findings", async () => {
    const graph = runtimeGraph();
    const policy = allowRuntimePolicy();
    const taintTracker = new TaintTracker();

    await handleJsonRpcLine(toolLine("read", "read_customer_profile", { customer_id: "cus_demo" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "audit-session",
      runtimeMode: "enforce"
    });

    const send = await handleJsonRpcLine(toolLine("send", "send_email", { to: "ops@example.test", body: "hello" }), {
      policy,
      graph,
      taintTracker,
      sessionId: "audit-session",
      runtimeMode: "audit-only"
    });
    expect(send.action).toBe("forward");
    expect(send.decision?.decision).toBe("allow");
    expect(send.decision?.attack_chain_findings?.length).toBeGreaterThan(0);
    expect(send.receipt?.runtime_mode).toBe("audit-only");
  });
});
