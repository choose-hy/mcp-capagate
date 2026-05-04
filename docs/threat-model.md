# Threat Model

MCP CapaGate focuses on MCP and AI-agent tool-call risks:

- tool poisoning through descriptions, examples, comments, and schema metadata
- hidden Unicode and bidi characters in tool metadata
- unexpected tool drift after server updates
- cross-server tool shadowing
- sensitive read followed by external send
- file write followed by command execution
- secrets or PII in tool responses

Out of scope for v0.1:

- cryptographic signing of receipts
- sandboxing the upstream MCP server process
- authentication for remote HTTP MCP deployments
- SaaS dashboards or hosted telemetry

The proxy fails closed when it cannot parse or evaluate a tool call.
