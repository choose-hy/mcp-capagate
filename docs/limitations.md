# Limitations

MCP CapaGate is a local-first guardrail for MCP and AI agent tool calls. It improves visibility and enforcement at the tool-call layer, but it is not a complete security boundary by itself.

## Not an OS Sandbox

MCP CapaGate is not an operating-system sandbox, container runtime, VM boundary, or process isolation layer. It can block or warn on tool calls that pass through its proxy, but it does not constrain what a malicious upstream process can do outside that path.

Run upstream MCP servers with OS-level least privilege:

- restrict filesystem access to the minimum required paths
- avoid running servers with administrator privileges
- isolate high-risk tools in containers or dedicated accounts when possible
- limit network access for servers that do not need it
- avoid sharing broad environment variables with MCP servers

## Malicious Servers Are Still Malicious

CapaGate cannot make a malicious MCP server safe by itself. A server can lie in its tool descriptions, expose dangerous behavior through innocent names, or perform side effects outside the declared tool schema.

CapaGate reduces risk by modeling declared capabilities, compiling policy, enforcing runtime decisions, and writing receipts. It should be combined with dependency review, server provenance checks, network controls, and least-privilege execution.

## Proxy Visibility

The runtime proxy only sees MCP messages routed through it. If an agent, client, or server bypasses the proxy, CapaGate cannot evaluate or block that call.

For production use, make sure the MCP client is configured so relevant `tools/call` traffic goes through `capagate wrap` or another CapaGate enforcement path.

## Rule-Based Extraction

Capability extraction in v0.1 is deterministic and rule-based. This keeps the MVP local and reproducible, but it can produce both false positives and false negatives.

Examples:

- a harmless tool name may match a risky keyword
- a risky capability may be hidden behind vague naming
- schema descriptions may be incomplete or misleading
- custom business semantics may require project-specific policy overrides

Review generated policies before relying on them for enforcement.

## Best-Effort Redaction

Response redaction is best-effort. It catches common patterns such as API keys, private keys, emails, phone numbers, credit-card-like numbers, and SSN-like values, but it is not a full data-loss prevention system.

Do not treat redaction as permission to expose secrets to tools, logs, demos, tests, or reports.

## Policy Overrides

Policy overrides should be reviewed carefully. An override that allows shell execution, external messaging, credential access, destructive operations, or financial actions can weaken the default least-privilege posture.

Prefer narrow overrides that match specific tools and document why they are needed.

## Demos and Test Data

Do not pass real secrets, production customer data, private credentials, or confidential documents into demos or tests. The example fixtures are synthetic and should stay synthetic.

## No LLM Dependency

MCP CapaGate does not require training data, fine-tuning, proprietary data, or an LLM API key. Optional LLM-assisted explanations may be useful in the future, but enforcement should remain deterministic and reviewable.