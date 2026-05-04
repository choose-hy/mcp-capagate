import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { parse as parsePath } from "node:path";
import { stringify as stringifyYaml } from "yaml";
import type { Command } from "commander";
import {
  AttackChainDetector,
  buildCapabilityGraph,
  compilePolicy,
  generateHtmlReport,
  generateMarkdownReport,
  handleJsonRpcLine,
  normalizeToolDefinitions,
  readAuditReceipts,
  type MCPToolDefinition,
  type ScanFinding
} from "@mcp-capagate/core";
import { collectScanFindings } from "./scan.js";

export function registerDemoCommand(program: Command): void {
  program
    .command("demo")
    .description("Run the deterministic MCP CapaGate demo using refund and poisoned tool schemas.")
    .action(async () => {
      await mkdir("reports", { recursive: true });
      await mkdir(".capagate", { recursive: true });
      await rm(".capagate/audit.jsonl", { force: true });

      const tools = [
        ...(await loadTools("examples/refund-server/tools.json", "refund-server")),
        ...(await loadTools("examples/poisoned-tools/tools.json", "poisoned-tools"))
      ];
      const graph0 = buildCapabilityGraph(tools, "demo");
      const findings = collectScanFindings(tools, graph0.nodes);
      const graph = buildCapabilityGraph(tools, "demo", findings);
      const policy = compilePolicy(graph);

      await writeFile("reports/scan.json", `${JSON.stringify(graph, null, 2)}\n`, "utf8");
      await writeFile("capagate.policy.yaml", stringifyYaml(policy), "utf8");

      const attackChainDetector = new AttackChainDetector();
      const simulation = [
        { tool: "read_order", args: { order_id: "ord_demo_1001" }, approve: false },
        { tool: "issue_refund", args: { order_id: "ord_demo_1001", amount: 42.5 }, approve: false },
        { tool: "execute_shell", args: { command: "echo synthetic-demo" }, approve: false },
        { tool: "read_customer_profile", args: { customer_id: "cus_demo_1" }, approve: true },
        { tool: "send_email", args: { to: "ops@example.test", body: "Synthetic demo message" }, approve: false }
      ];

      const decisions: string[] = [];
      const attackFindings: ScanFinding[] = [];
      for (const call of simulation) {
        const line = JSON.stringify({ jsonrpc: "2.0", id: call.tool, method: "tools/call", params: { name: call.tool, arguments: call.args } });
        const result = await handleJsonRpcLine(line, {
          policy,
          graph,
          auditLogPath: ".capagate/audit.jsonl",
          sessionId: "demo",
          interactive: call.approve,
          approve: () => call.approve,
          attackChainDetector
        });
        decisions.push(`${call.tool}: ${(result.decision?.decision ?? "forward").toUpperCase()} - ${result.decision?.reason ?? result.line}`);
        if (result.decision?.required_controls.includes("attack_chain_block")) {
          attackFindings.push({
            id: `demo-${call.tool}`,
            type: "external_network_sink",
            severity: "critical",
            tool: call.tool,
            message: result.decision.reason,
            recommendation: "Block external sends after sensitive reads unless the session is explicitly approved."
          });
        }
      }

      const audit = readAuditReceipts(".capagate/audit.jsonl");
      await writeFile("reports/summary.md", generateMarkdownReport({ graph, policy, audit, attackFindings }), "utf8");
      await writeFile("reports/index.html", generateHtmlReport({ graph, policy, audit, attackFindings }), "utf8");

      console.log("MCP CapaGate demo complete.");
      for (const decision of decisions) {
        console.log(`- ${decision}`);
      }
      console.log("Generated reports/scan.json, capagate.policy.yaml, reports/summary.md, reports/index.html, .capagate/audit.jsonl");
    });
}

async function loadTools(path: string, server: string): Promise<MCPToolDefinition[]> {
  const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
  return normalizeToolDefinitions(raw, server).map((tool) => ({ ...tool, server: tool.server ?? serverName(path) ?? server }));
}

function serverName(path: string): string | undefined {
  const parsed = parsePath(path);
  return parsed.dir.split(/[\\/]/).at(-1);
}
