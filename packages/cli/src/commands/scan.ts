import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Command } from "commander";
import {
  buildCapabilityGraph,
  collectScanFindings,
  normalizeToolDefinitions,
  type CapabilityGraph,
  type MCPToolDefinition
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

async function inputsFromConfig(configPath: string): Promise<string[]> {
  const absolute = resolve(configPath);
  const config = parseYaml(await readFile(absolute, "utf8")) as { inputs?: { tools?: string | string[] } };
  const tools = config.inputs?.tools;
  if (!tools) {
    throw new Error(`No inputs.tools found in ${configPath}. Pass --input or configure capagate.yaml.`);
  }
  return (Array.isArray(tools) ? tools : [tools]).map((item) => resolve(dirname(absolute), item));
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
