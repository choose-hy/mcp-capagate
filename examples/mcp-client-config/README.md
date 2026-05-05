# MCP Client Config Discovery Example

This directory contains a safe synthetic MCP client config shaped like common
desktop MCP configuration files.

The example records three local MCP-like servers:

- `filesystem`: file read/write style tools
- `refunds`: billing and refund tools
- `email`: outbound message tools

The commands are placeholders. They are not real servers and do not require
credentials.

## Inventory Discovery

Inventory mode parses the config and records server commands without starting
anything:

```bash
capagate discover --mcp-config examples/mcp-client-config/claude_desktop_config.example.json --out reports/discovered-tools.json
```

The output includes server names, commands, args, and instructions for probe
mode. `expected-discovery.json` shows the intended shape with a fixed timestamp
for readability.

## Probe Mode

Probe mode starts each configured server and sends a minimal line-delimited
JSON-RPC `initialize` plus `tools/list` request:

```bash
capagate discover --mcp-config examples/mcp-client-config/claude_desktop_config.example.json --probe --out reports/discovered-tools.json
```

Probe mode is best-effort. Some MCP servers use framed stdio transports, need
credentials, or require interactive setup. In those cases CapaGate records an
error for that server instead of guessing.

## Follow-On Baseline

After discovery produces tools, scan and baseline them:

```bash
capagate scan --input reports/discovered-tools.json --out reports/scan.json
capagate baseline save --scan reports/scan.json --out .capagate/baseline.json
capagate baseline verify --baseline .capagate/baseline.json --current reports/scan.json --fail-on high
```
