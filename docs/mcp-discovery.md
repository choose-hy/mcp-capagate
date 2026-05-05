# MCP Discovery

MCP CapaGate can discover MCP server inventory from common client config files
so teams do not have to hand-write `tools.json` before scanning.

## Supported Config Shape

CapaGate supports JSON configs with an `mcpServers` object:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "./workspace"]
    },
    "email": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}
```

Each server entry is normalized into:

- server name
- command
- args
- optional environment values
- optional working directory
- disabled flag

## Inventory Mode

Inventory mode is the default and does not start any server:

```bash
capagate discover --mcp-config claude_desktop_config.json --out reports/discovered-tools.json
```

The output records server inventory and next-step instructions. It is safe for
CI because it does not execute configured MCP server commands.

## Probe Mode

Probe mode starts each configured server and attempts a minimal JSON-RPC
handshake:

```bash
capagate discover --mcp-config claude_desktop_config.json --probe --out reports/discovered-tools.json
```

The MVP probe sends:

1. `initialize`
2. `notifications/initialized`
3. `tools/list`

Discovered tools are normalized into `MCPToolDefinition` objects under the
top-level `tools` field, so the output can be used by `capagate scan`.

## Limitations

Probe mode is intentionally conservative and best-effort. It uses
line-delimited JSON-RPC over stdio and may not work for servers that require
framed stdio transport, credentials, network access, interactive prompts, or
long startup time.

Do not run probe mode on untrusted MCP server configs. Inventory mode is the
right default for reviewing unknown configs.
