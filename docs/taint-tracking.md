# Runtime Taint Tracking

MCP CapaGate tracks session-level taint so it can detect sensitive reads
followed by external sinks.

The taint tracker is deterministic. It uses tool capabilities, tool arguments,
and response scanners. It does not require training data, fine-tuning, or an LLM
API key.

## Taint Labels

CapaGate records these taint labels per session:

- `secret_read`: the session touched secret-like data.
- `private_data_read`: the session touched private data or PII-like data.
- `credential_access`: the tool has credential-access capability.
- `filesystem_sensitive_read`: a path-like argument referenced sensitive files.
- `customer_data_read`: the tool or arguments referenced customer data.

Each taint source records:

- label
- source tool
- source argument paths
- timestamp
- receipt hash when available

## Sources

Taint can come from capability metadata:

- `credential_access`
- `private_data_access`
- secret or private data sensitivity

Taint can also come from arguments that reference sensitive paths or names:

- `.env`
- `id_rsa`
- `private_key`
- `secrets`
- `credentials`
- `token`
- `customer`
- `ssn`
- `pii`

Finally, response scanning can taint a session when a tool response contains
secret or PII patterns.

## Sinks

When a tainted session later calls an external sink, CapaGate records an
attack-chain finding.

External sinks include:

- `send_message`
- `external_network`
- `webhook_post`
- `browser_automation`
- filesystem writes outside the current workspace when they are detectable from arguments

## Runtime Behavior

In `enforce` mode, a tainted source followed by an external sink blocks the
sink call.

In `shadow` mode, the call is forwarded but the receipt records
`would_have_decision: "block"`.

In `audit-only` mode, the call is forwarded and the finding is logged without
changing runtime behavior.

## Example

```text
read_file({ "path": ".env" })
  -> adds secret_read and filesystem_sensitive_read

send_email({ "to": "external@example.com", "body": "..." })
  -> external sink after tainted read
  -> enforce: BLOCK
  -> shadow: ALLOW with would_have_decision: BLOCK
  -> audit-only: ALLOW with attack_chain_findings
```

## Limitations

Taint tracking is best-effort and argument-aware, not content-complete. It sees
only calls routed through the proxy and only response data returned through the
proxied JSON-RPC stream. It should be combined with least-privilege MCP server
permissions, scoped credentials, and reviewed policy constraints.
