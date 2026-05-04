import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, compilePolicy, handleJsonRpcLine, normalizeToolDefinitions, redactResponseLine } from "../packages/core/src/index.js";

describe("stdio proxy helpers", () => {
  it("passes through non-tool JSON-RPC messages", async () => {
    const graph = buildCapabilityGraph([], "proxy-test");
    const policy = compilePolicy(graph);
    const line = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    const result = await handleJsonRpcLine(line, { policy });
    expect(result.action).toBe("forward");
    expect(result.line).toBe(line);
  });

  it("blocks a synthetic shell tool call", async () => {
    const tools = normalizeToolDefinitions([
      {
        name: "execute_shell",
        description: "Execute shell command.",
        inputSchema: { type: "object", properties: { command: { type: "string" } } }
      }
    ]);
    const graph = buildCapabilityGraph(tools, "proxy-test");
    const policy = compilePolicy(graph);
    const line = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "execute_shell", arguments: { command: "echo synthetic" } } });
    const result = await handleJsonRpcLine(line, { policy, graph });
    expect(result.action).toBe("respond");
    expect(result.line).toContain("blocked");
  });

  it("redacts secrets and PII from response lines", () => {
    const redacted = redactResponseLine('{"email":"dev@example.com","key":"sk-abcdefghijklmnopqrstuvwxyz"}');
    expect(redacted).toContain("[REDACTED_EMAIL]");
    expect(redacted).toContain("sk-[REDACTED]");
  });
});
