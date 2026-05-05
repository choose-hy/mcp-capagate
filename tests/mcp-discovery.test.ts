import { describe, expect, it } from "vitest";
import { discoverMcpClientConfig, parseMcpClientConfig } from "../packages/core/src/index.js";

const clientConfig = {
  mcpServers: {
    filesystem: {
      command: "npx",
      args: ["@modelcontextprotocol/server-filesystem", "./workspace"]
    },
    email: {
      command: "node",
      args: ["server.js"],
      env: { MCP_ENV: "synthetic" }
    }
  }
};

describe("MCP client config discovery", () => {
  it("parses mcpServers config entries", () => {
    const servers = parseMcpClientConfig(clientConfig);
    expect(servers).toHaveLength(2);
    expect(servers[0]).toMatchObject({
      name: "filesystem",
      command: "npx",
      args: ["@modelcontextprotocol/server-filesystem", "./workspace"]
    });
    expect(servers[1]).toMatchObject({
      name: "email",
      command: "node",
      args: ["server.js"],
      env: { MCP_ENV: "synthetic" }
    });
  });

  it("normalizes server inventory without probing", async () => {
    const report = await discoverMcpClientConfig(clientConfig, {
      source: "claude_desktop_config.json",
      probe: false
    });
    expect(report.probe).toBe(false);
    expect(report.servers.map((server) => server.status)).toEqual(["inventory", "inventory"]);
    expect(report.servers[0]?.instructions).toContain("--probe");
    expect(report.tools).toEqual([]);
  });
});
