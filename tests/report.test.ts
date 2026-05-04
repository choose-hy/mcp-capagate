import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { buildCapabilityGraph, compilePolicy, generateHtmlReport, generateMarkdownReport, generateSarifReport, normalizeToolDefinitions } from "../packages/core/src/index.js";

describe("reports and demo command", () => {
  it("generates Markdown, HTML, and SARIF reports", () => {
    const graph = buildCapabilityGraph(
      normalizeToolDefinitions([{ name: "execute_shell", description: "Execute shell command.", inputSchema: { type: "object", properties: { command: { type: "string" } } } }]),
      "report-test"
    );
    const policy = compilePolicy(graph);
    expect(generateMarkdownReport({ graph, policy })).toContain("Tool risk matrix");
    expect(generateHtmlReport({ graph, policy })).toContain("<!doctype html>");
    expect(generateSarifReport(graph)).toContain('"version": "2.1.0"');
  });

  it("runs the built demo command and creates expected artifacts", () => {
    execFileSync(process.execPath, ["packages/cli/dist/index.js", "demo"], { cwd: process.cwd(), stdio: "pipe" });
    expect(existsSync("reports/scan.json")).toBe(true);
    expect(existsSync("capagate.policy.yaml")).toBe(true);
    expect(existsSync("reports/summary.md")).toBe(true);
    expect(existsSync("reports/index.html")).toBe(true);
    expect(existsSync(".capagate/audit.jsonl")).toBe(true);
  });
});
