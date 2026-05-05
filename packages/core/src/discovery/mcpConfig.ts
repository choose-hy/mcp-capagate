import { z } from "zod";
import type { MCPDiscoveryReport, MCPDiscoveryServerResult, MCPServerConfig } from "../types.js";
import { normalizeToolDefinitions } from "../schema.js";
import { probeMcpServerTools } from "./mcpProbe.js";

const serverConfigSchema = z
  .object({
    command: z.string().min(1),
    args: z.array(z.string()).optional().default([]),
    env: z.record(z.string(), z.string()).optional(),
    cwd: z.string().optional(),
    disabled: z.boolean().optional()
  })
  .passthrough();

const mcpClientConfigSchema = z
  .object({
    mcpServers: z.record(z.string(), serverConfigSchema)
  })
  .passthrough();

export interface DiscoverMcpClientConfigOptions {
  source: string;
  probe?: boolean;
  timeoutMs?: number;
}

export function parseMcpClientConfig(raw: unknown): MCPServerConfig[] {
  const parsed = mcpClientConfigSchema.parse(raw);
  return Object.entries(parsed.mcpServers).map(([name, server]) => ({
    name,
    command: server.command,
    args: server.args ?? [],
    env: server.env,
    cwd: server.cwd,
    disabled: server.disabled
  }));
}

export async function discoverMcpClientConfig(raw: unknown, options: DiscoverMcpClientConfigOptions): Promise<MCPDiscoveryReport> {
  const servers = parseMcpClientConfig(raw);
  const results: MCPDiscoveryServerResult[] = [];

  for (const server of servers) {
    if (!options.probe || server.disabled) {
      results.push({
        ...server,
        status: "inventory",
        tools: [],
        instructions: server.disabled
          ? "Server is marked disabled; probe was skipped."
          : "Run discover with --probe to start this server and request tools/list."
      });
      continue;
    }

    const probe = await probeMcpServerTools(server, { timeoutMs: options.timeoutMs });
    results.push(probe);
  }

  const tools = results.flatMap((result) => normalizeToolsForServer(result));
  return {
    generated_at: new Date().toISOString(),
    source: options.source,
    probe: Boolean(options.probe),
    servers: results,
    tools,
    instructions: [
      "Without --probe, discovery records MCP server inventory only.",
      "With --probe, CapaGate starts each server and sends initialize plus tools/list over line-delimited JSON-RPC.",
      "Probe mode is best-effort and may not work for servers that require framed stdio transport, credentials, or interactive setup."
    ]
  };
}

function normalizeToolsForServer(result: MCPDiscoveryServerResult) {
  if (result.tools.length === 0) {
    return [];
  }
  return normalizeToolDefinitions(result.tools, result.name);
}
