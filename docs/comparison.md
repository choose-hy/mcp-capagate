# Comparison

MCP CapaGate is a capability-aware policy compiler and runtime firewall for MCP tool calls. It overlaps with scanners, guardrails, observability, and sandboxing, but it is not a replacement for all of them.

## MCP CapaGate vs MCP Scanners

MCP scanners usually inspect tool definitions and report suspicious descriptions, schemas, or metadata. That is useful for discovery, but scanning alone does not decide what should happen when an agent tries to call a tool.

CapaGate goes further:

- models tools as capability nodes
- links risky combinations in a Capability Graph
- compiles least-privilege policy
- enforces `ALLOW`, `WARN`, `REQUIRE_APPROVAL`, and `BLOCK` at runtime
- writes audit receipts and reports

Short version: a scanner finds risks; CapaGate models capabilities, compiles policy, and enforces runtime decisions.

## MCP CapaGate vs Generic LLM Guardrails

Generic LLM guardrails often operate at the model, prompt, or text-output layer. They can help with prompt classification, response filtering, policy reminders, and unsafe content detection.

CapaGate operates at the tool-call layer. It evaluates the concrete MCP tool name, arguments, declared capabilities, compiled policy, and session attack-chain state before a `tools/call` reaches the upstream server.

This makes CapaGate complementary to model-level guardrails. Prompt defenses can reduce bad instructions; CapaGate can still block dangerous tool execution when instructions slip through.

## MCP CapaGate vs Observability Tools

Observability tools help teams see what happened: traces, logs, metrics, spans, and dashboards. They are important for debugging and incident response, but many observability systems are primarily retrospective.

CapaGate can act before execution. It can block a risky tool call, require approval, redact risky responses, and produce a receipt that explains the decision.

Short version: observability sees what happened; CapaGate can block before execution.

## MCP CapaGate vs OS Sandboxing

OS sandboxing provides process-level or system-level isolation. Examples include containers, VMs, restricted users, filesystem permissions, seccomp, and network controls. These controls are essential when running untrusted or high-risk MCP servers.

CapaGate is a semantic tool-policy layer. It understands tool schemas, capabilities, risk levels, policy rules, drift, and attack-chain state. It does not replace process isolation.

Use both layers together:

- OS sandboxing limits what a server process can do
- CapaGate limits what tool calls an agent is allowed to request
- audit receipts explain why each runtime decision was made

A strong deployment treats CapaGate as one control in a defense-in-depth stack, not as the only boundary.