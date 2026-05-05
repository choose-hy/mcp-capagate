import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import type { MCPDiscoveryServerResult, MCPServerConfig } from "../types.js";
import { normalizeToolDefinitions } from "../schema.js";
import { stringifyJsonRpc, type JsonRpcResponse } from "../proxy/jsonRpc.js";

export interface ProbeMcpServerOptions {
  timeoutMs?: number;
}

export async function probeMcpServerTools(server: MCPServerConfig, options: ProbeMcpServerOptions = {}): Promise<MCPDiscoveryServerResult> {
  const timeoutMs = options.timeoutMs ?? 5000;
  const child = spawn(server.command, server.args, {
    cwd: server.cwd,
    env: server.env ? { ...process.env, ...server.env } : process.env,
    stdio: ["pipe", "pipe", "pipe"],
    shell: process.platform === "win32"
  });

  const stderr: string[] = [];
  child.stderr.on("data", (chunk) => {
    stderr.push(String(chunk));
  });
  const spawnError = new Promise<JsonRpcResponse>((_, reject) => {
    child.once("error", reject);
  });

  const responses = new Map<string, (response: JsonRpcResponse) => void>();
  const stdout = createInterface({ input: child.stdout });
  stdout.on("line", (line) => {
    try {
      const response = JSON.parse(line) as JsonRpcResponse;
      const resolver = responses.get(String(response.id));
      if (resolver) {
        resolver(response);
      }
    } catch {
      return;
    }
  });

  const waitForResponse = (id: string): Promise<JsonRpcResponse> =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        responses.delete(id);
        reject(new Error(`Timed out waiting for JSON-RPC response ${id}.`));
      }, timeoutMs);
      responses.set(id, (response) => {
        clearTimeout(timer);
        responses.delete(id);
        resolve(response);
      });
    });

  try {
    child.stdin.write(
      `${stringifyJsonRpc({
        jsonrpc: "2.0",
        id: "capagate-init",
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "mcp-capagate", version: "0.2.0" }
        }
      })}\n`
    );
    const initialize = await Promise.race([waitForResponse("capagate-init"), spawnError]);
    if (initialize.error) {
      throw new Error(initialize.error.message);
    }

    child.stdin.write(`${stringifyJsonRpc({ jsonrpc: "2.0", method: "notifications/initialized", params: {} })}\n`);
    child.stdin.write(`${stringifyJsonRpc({ jsonrpc: "2.0", id: "capagate-tools", method: "tools/list", params: {} })}\n`);
    const toolsList = await Promise.race([waitForResponse("capagate-tools"), spawnError]);
    if (toolsList.error) {
      throw new Error(toolsList.error.message);
    }

    const tools = normalizeToolDefinitions(toolsList.result, server.name);
    return {
      ...server,
      status: "probed",
      tools
    };
  } catch (error) {
    return {
      ...server,
      status: "error",
      tools: [],
      error: error instanceof Error ? error.message : String(error),
      instructions: stderr.length > 0 ? stderr.join("").slice(0, 1000) : "Probe failed before tools/list completed."
    };
  } finally {
    if (!child.killed) {
      child.kill();
    }
  }
}
