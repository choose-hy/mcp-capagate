import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Command } from "commander";
import { discoverMcpClientConfig, normalizeToolDefinitions } from "@mcp-capagate/core";

export function registerDiscoverCommand(program: Command): void {
  program
    .command("discover")
    .description("Normalize local MCP tools JSON or discover MCP servers from client config.")
    .option("-i, --input <path>", "input JSON")
    .option("--mcp-config <path>", "MCP client config JSON with mcpServers")
    .option("--probe", "start configured MCP servers and request tools/list", false)
    .option("--timeout <ms>", "probe timeout in milliseconds", "5000")
    .option("-o, --out <path>", "normalized tools JSON")
    .action(async (options: { input?: string; mcpConfig?: string; probe: boolean; timeout: string; out?: string }) => {
      if (!options.input && !options.mcpConfig) {
        throw new Error("Pass --input for tools JSON or --mcp-config for MCP client config discovery.");
      }

      if (options.input && options.mcpConfig) {
        throw new Error("Use either --input or --mcp-config, not both.");
      }

      const output = options.mcpConfig ? await discoverFromMcpConfig(options.mcpConfig, options.probe, options.timeout) : await normalizeFromInput(options.input ?? "");
      await writeOutput(output, options.out);
    });
}

async function normalizeFromInput(path: string): Promise<unknown> {
  const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
  return normalizeToolDefinitions(raw);
}

async function discoverFromMcpConfig(path: string, probe: boolean, timeout: string): Promise<unknown> {
  const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
  return discoverMcpClientConfig(raw, {
    source: path,
    probe,
    timeoutMs: parseTimeout(timeout)
  });
}

function parseTimeout(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Invalid probe timeout ${value}. Expected a positive number of milliseconds.`);
  }
  return parsed;
}

async function writeOutput(value: unknown, out?: string): Promise<void> {
  const output = `${JSON.stringify(value, null, 2)}\n`;
  if (out) {
    await mkdir(dirname(out), { recursive: true });
    await writeFile(out, output, "utf8");
    return;
  }
  process.stdout.write(output);
}
