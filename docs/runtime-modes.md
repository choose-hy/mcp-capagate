# Runtime Modes

MCP CapaGate can run the runtime proxy in three deterministic modes:
`enforce`, `shadow`, and `audit-only`.

Use runtime modes to move from observation to blocking without changing MCP
server code or requiring an LLM API.

## Mode Summary

| Mode | Behavior | Typical use |
| --- | --- | --- |
| `enforce` | Blocks `BLOCK` decisions and blocks `REQUIRE_APPROVAL` when approval is not granted. | Production enforcement for reviewed policies. |
| `shadow` | Forwards every call, but records what would have been blocked or required approval. | Rollout testing, policy tuning, and adoption in existing agent stacks. |
| `audit-only` | Forwards every call and records policy, capability, taint, and attack-chain observations. | Passive monitoring, baselining, and early integration. |

## Enforce

`enforce` is the default runtime mode.

```bash
capagate wrap --mode enforce --policy capagate.policy.yaml --scan reports/scan.json -- npx your-mcp-server
```

In enforce mode:

- `ALLOW` and `WARN` calls are forwarded.
- `REQUIRE_APPROVAL` is forwarded only when interactive approval succeeds.
- `BLOCK` returns a JSON-RPC error before the upstream MCP server sees the call.
- Attack-chain and taint findings can escalate a risky call to `BLOCK`.

## Shadow

Shadow mode never blocks a tool call. It forwards the call and records the
decision that would have happened in enforce mode.

```bash
capagate wrap --mode shadow --policy capagate.policy.yaml --scan reports/scan.json -- npx your-mcp-server
```

Receipts produced in shadow mode include:

- `runtime_mode: "shadow"`
- `would_have_decision` when a call would have been blocked or required approval
- `taint_labels` when sensitive session state is involved
- `attack_chain_findings` when a risky sequence is detected

Shadow mode is useful when introducing CapaGate to an existing MCP deployment:
teams can inspect real policy impact before turning on blocking.

## Audit-Only

Audit-only mode disables policy blocking and approval behavior. It records
capability, policy, taint, and attack-chain context but always forwards calls.

```bash
capagate wrap --mode audit-only --policy capagate.policy.yaml --scan reports/scan.json -- npx your-mcp-server
```

Use audit-only mode for early baselines or environments where CapaGate should
not affect runtime behavior yet.

## Receipt Fields

Runtime receipts can include:

- `runtime_mode`: `enforce`, `shadow`, or `audit-only`
- `would_have_decision`: the enforce-mode decision when shadow mode forwarded a risky call
- `taint_labels`: session labels such as `secret_read` or `private_data_read`
- `attack_chain_findings`: structured findings explaining risky tool sequences

## Limitations

Runtime mode only applies to calls routed through the CapaGate proxy. It is not
an OS sandbox and cannot constrain an MCP server that is run outside the proxy.
Use OS-level least privilege for upstream servers and review policy overrides
before relying on enforce mode in production.
