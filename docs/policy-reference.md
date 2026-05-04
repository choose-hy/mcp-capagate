# Policy Reference

Policy rules are priority ordered. The first matching high-priority rule determines the runtime decision.

Decisions:

- `allow`: forward the tool call.
- `warn`: forward the tool call and log a warning receipt.
- `require_approval`: require an interactive approval. Non-interactive mode blocks.
- `block`: return a JSON-RPC error without forwarding the call.

Default compiler behavior:

- Low-risk read-only tools are allowed.
- Medium-risk or unknown tools warn.
- Private data, financial actions, write operations, and external messages require approval.
- Shell execution, arbitrary code execution, credential exfiltration, and destructive operations are blocked by default.

The policy hash is computed with stable SHA-256 over deterministic policy content.
