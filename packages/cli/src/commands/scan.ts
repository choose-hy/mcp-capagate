import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Command } from "commander";
import {
  buildCapabilityGraph,
  normalizeToolDefinitions,
  scanAllHiddenUnicode,
  scanAllSchemaInjection,
  scanAllToolPoisoning,
  sha256,
  type CapabilityGraph,
  type CapabilityNode,
  type MCPToolDefinition,
  type ScanFinding
} from "@mcp-capagate/core";

export function registerScanCommand(program: Command): void {
  program
    .command("scan")
    .description("Load MCP tool definitions, build a capability graph, and detect risky tool metadata.")
    .option("-i, --input <path>", "JSON file containing local tools, { tools }, or tools/list response")
    .option("-c, --config <path>", "capagate.yaml config file", "capagate.yaml")
    .option("-o, --out <path>", "output capability graph JSON", "reports/scan.json")
    .action(async (options: { input?: string; config: string; out: string }) => {
      const inputs = options.input ? [options.input] : await inputsFromConfig(options.config);
      const graph = await scanInputFiles(inputs);
      await writeJson(options.out, graph);
      printRiskSummary(graph);
    });
}

export async function scanInputFiles(inputs: string[]): Promise<CapabilityGraph> {
  const tools: MCPToolDefinition[] = [];
  for (const input of inputs) {
    const raw = JSON.parse(await readFile(input, "utf8")) as unknown;
    const server = serverNameFromPath(input);
    tools.push(...normalizeToolDefinitions(raw, server));
  }

  const graphWithoutFindings = buildCapabilityGraph(tools, inputs.join(","));
  const findings = collectScanFindings(tools, graphWithoutFindings.nodes);
  return buildCapabilityGraph(tools, inputs.join(","), findings);
}

export function collectScanFindings(tools: MCPToolDefinition[], nodes: CapabilityNode[]): ScanFinding[] {
  const findings = [
    ...scanAllToolPoisoning(tools),
    ...scanAllHiddenUnicode(tools),
    ...scanAllSchemaInjection(tools),
    ...detectAmbiguousToolNames(tools),
    ...detectCrossServerShadowing(tools),
    ...detectParameterNames(tools),
    ...detectRiskyCapabilities(nodes),
    ...detectExternalNetworkSinks(nodes)
  ];
  return dedupeFindings(findings);
}

async function inputsFromConfig(configPath: string): Promise<string[]> {
  const absolute = resolve(configPath);
  const config = parseYaml(await readFile(absolute, "utf8")) as { inputs?: { tools?: string | string[] } };
  const tools = config.inputs?.tools;
  if (!tools) {
    throw new Error(`No inputs.tools found in ${configPath}. Pass --input or configure capagate.yaml.`);
  }
  return (Array.isArray(tools) ? tools : [tools]).map((item) => resolve(dirname(absolute), item));
}

function detectAmbiguousToolNames(tools: MCPToolDefinition[]): ScanFinding[] {
  return tools
    .filter((tool) => /^(run|do|call|tool|execute|get|send|process)$/i.test(tool.name) || tool.name.length < 4)
    .map((tool) => ({
      id: sha256(`ambiguous:${tool.server ?? ""}:${tool.name}`).slice(0, 16),
      type: "ambiguous_tool_name" as const,
      severity: "medium" as const,
      tool: tool.name,
      server: tool.server,
      message: `Tool name ${tool.name} is ambiguous and may hide capability intent.`,
      recommendation: "Use verb-object names such as read_order or send_refund_email."
    }));
}

function detectCrossServerShadowing(tools: MCPToolDefinition[]): ScanFinding[] {
  const byName = new Map<string, MCPToolDefinition[]>();
  for (const tool of tools) {
    const same = byName.get(tool.name) ?? [];
    same.push(tool);
    byName.set(tool.name, same);
  }
  return [...byName.values()].flatMap((sameNameTools) => {
    const servers = new Set(sameNameTools.map((tool) => tool.server ?? "local"));
    if (servers.size < 2) {
      return [];
    }
    return sameNameTools.map((tool) => ({
      id: sha256(`shadow:${tool.name}:${tool.server ?? "local"}`).slice(0, 16),
      type: "cross_server_shadowing" as const,
      severity: "medium" as const,
      tool: tool.name,
      server: tool.server,
      message: `Tool ${tool.name} appears across multiple servers.`,
      recommendation: "Namespace tools or pin policies to server identity."
    }));
  });
}

function detectParameterNames(tools: MCPToolDefinition[]): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const tool of tools) {
    for (const path of collectObjectKeys(tool.inputSchema, "inputSchema")) {
      if (/(api[_-]?key|token|secret|password|credential|private[_-]?key)/i.test(path)) {
        findings.push({
          id: sha256(`secret_param:${tool.server ?? ""}:${tool.name}:${path}`).slice(0, 16),
          type: "secret",
          severity: "high",
          tool: tool.name,
          server: tool.server,
          path,
          message: `Secret-related parameter name detected at ${path}.`,
          recommendation: "Avoid passing secrets through agent-visible tool arguments."
        });
      }
      if (/(ssn|phone|email|address|customer|profile|pii)/i.test(path)) {
        findings.push({
          id: sha256(`pii_param:${tool.server ?? ""}:${tool.name}:${path}`).slice(0, 16),
          type: "pii",
          severity: "medium",
          tool: tool.name,
          server: tool.server,
          path,
          message: `PII-related parameter name detected at ${path}.`,
          recommendation: "Minimize private fields and redact responses by default."
        });
      }
    }
  }
  return findings;
}

function detectRiskyCapabilities(nodes: CapabilityNode[]): ScanFinding[] {
  return nodes
    .filter((node) => node.risk_level === "high" || node.risk_level === "critical")
    .map((node) => ({
      id: sha256(`risky:${node.server ?? ""}:${node.tool}:${node.risk_level}`).slice(0, 16),
      type: "risky_capability" as const,
      severity: node.risk_level,
      tool: node.tool,
      server: node.server,
      message: `${node.tool} has ${node.risk_level} capability risk.`,
      evidence: node.capabilities.join(", "),
      recommendation: "Compile and enforce a least-privilege policy before runtime use."
    }));
}

function detectExternalNetworkSinks(nodes: CapabilityNode[]): ScanFinding[] {
  return nodes
    .filter((node) => node.capabilities.some((capability) => capability === "external_network" || capability === "send_message" || capability === "webhook_post"))
    .map((node) => ({
      id: sha256(`sink:${node.server ?? ""}:${node.tool}`).slice(0, 16),
      type: "external_network_sink" as const,
      severity: "high" as const,
      tool: node.tool,
      server: node.server,
      message: `${node.tool} can send data to an external sink.`,
      evidence: node.capabilities.join(", "),
      recommendation: "Require destination allowlists and response redaction for this tool."
    }));
}

function collectObjectKeys(value: unknown, path: string): string[] {
  if (!value || typeof value !== "object") {
    return [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectObjectKeys(item, `${path}[${index}]`));
  }
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => [`${path}.${key}`, ...collectObjectKeys(child, `${path}.${key}`)]);
}

function dedupeFindings(findings: ScanFinding[]): ScanFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    if (seen.has(finding.id)) {
      return false;
    }
    seen.add(finding.id);
    return true;
  });
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function printRiskSummary(graph: CapabilityGraph): void {
  console.log(`MCP CapaGate scan complete: ${graph.summary.tool_count} tools, ${graph.summary.risk_counts.critical} critical, ${graph.summary.risk_counts.high} high, ${graph.findings?.length ?? 0} findings.`);
  console.log(`Graph hash: ${graph.graph_hash}`);
}

function serverNameFromPath(input: string): string {
  const parts = input.replaceAll("\\", "/").split("/");
  return parts.at(-2) ?? "local";
}
