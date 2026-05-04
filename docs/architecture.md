# Architecture

MCP CapaGate is local-first and deterministic. It does not call an LLM, does not store data in a database, and does not emit telemetry.

The pipeline has five stages:

1. Discovery normalizes MCP `tools/list` responses and local JSON arrays into `MCPToolDefinition`.
2. Extraction maps names, descriptions, schemas, annotations, and server identity into a capability set.
3. Graph building creates capability nodes, attack-chain edges, shadowing edges, summaries, and a stable graph hash.
4. Policy compilation emits priority-ordered least-privilege rules.
5. Runtime enforcement intercepts line-delimited JSON-RPC `tools/call` messages through a transparent stdio proxy.

The MVP intentionally favors deterministic evidence over model-generated explanations. Future versions may add optional LLM-assisted summaries, but policy decisions remain deterministic.
