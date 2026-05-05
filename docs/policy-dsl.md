# Policy DSL

MCP CapaGate policies can combine capability-aware decisions with deterministic argument constraints. Capability and risk rules decide whether a tool is generally allowed, warned, approval-gated, or blocked. Constraints then check the concrete `tools/call` arguments before the call is forwarded.

This keeps the model simple:

```text
Tool capability -> Policy rule -> Argument constraints -> Runtime decision
```

If a constraint fails, CapaGate fails closed and returns `BLOCK` with a structured constraint finding.

## Constraint Types

A policy rule can include a `constraints` object.

```yaml
rules:
  - id: example.read_file.docs_only
    match:
      tool: read_file
    decision: allow
    reason: "Allow docs reads only."
    constraints:
      path_prefixes:
        - "./docs/"
      required_argument_paths:
        - path
    controls:
      - path_allowlist
      - constraint_review
    priority: 1000
```

Supported constraints:

- `path_prefixes`: allow path-like arguments only under approved prefixes.
- `allowed_domains`: allow email, URL, webhook, or endpoint arguments only when their domain or host matches the allowlist.
- `blocked_domains`: block email, URL, webhook, or endpoint arguments when their domain or host matches the blocklist.
- `max_amount`: block amount-like numeric arguments above the configured limit.
- `required_boolean_flags`: require boolean flags such as `confirmed=true` or `approval.confirmed=true`.
- `blocked_argument_patterns`: block a specific argument path when a regular expression matches its value.
- `required_argument_paths`: require an argument key or nested path to exist.
- `blocked_argument_paths`: block a call when an argument key or nested path exists.

## Examples

### Restrict File Reads

```yaml
constraints:
  path_prefixes:
    - "./docs/"
    - "docs/"
  required_argument_paths:
    - path
```

This allows `read_file({ "path": "docs/runbook.md" })` and blocks `read_file({ "path": "../private.env" })`.

### Require Refund Confirmation

```yaml
constraints:
  max_amount: 100
  required_boolean_flags:
    - confirmed
```

This allows policy evaluation to proceed for `issue_refund({ "amount": 50, "confirmed": true })` and blocks calls with missing confirmation or an amount above `100`.

### Allow Company Email Only

```yaml
constraints:
  allowed_domains:
    - company.com
  required_argument_paths:
    - to
```

This allows `security@company.com` and `alerts.eu.company.com`, but blocks external domains.

### Block Dangerous Command Patterns

```yaml
constraints:
  blocked_argument_patterns:
    - path: command
      pattern: "rm\\s+-rf|curl\\s+.*\\|\\s*sh"
      reason: "Dangerous shell command pattern."
```

Patterns are deterministic regular expressions. Invalid regexes fail closed.

## Fail-Closed Behavior

When a matched policy rule has constraints and any constraint fails:

- the final decision becomes `BLOCK`
- the reason includes the failed constraint
- `constraint_review` is added to `required_controls`
- structured `constraint_findings` are attached to the policy decision

If constraints pass, CapaGate keeps the original rule decision. For example, a financial tool may still return `REQUIRE_APPROVAL` after passing `max_amount` and `confirmed=true` checks.

## Argument Paths

Argument paths use dot notation for nested objects:

```yaml
constraints:
  required_boolean_flags:
    - approval.confirmed
  blocked_argument_paths:
    - debug.raw_token
```

Simple names such as `confirmed` match that key anywhere in the argument object. Explicit paths such as `approval.confirmed` match the nested path.

## Default Compiler Constraints

The policy compiler adds conservative defaults for common risky capabilities:

- `filesystem_read`: `path_prefixes: ["./", "docs/", "examples/"]`
- `financial_action`: `max_amount: 100` and `required_boolean_flags: ["confirmed"]`
- `webhook_post`: `allowed_domains: []`
- `shell_execution`: blocked by the existing least-privilege policy

These defaults are intentionally not permissive. Review and adapt generated policy before production use.

## Limitations

The Policy DSL is deterministic and local, but it is not a sandbox. It only evaluates tool calls routed through CapaGate. Path checks are conservative string checks and should be paired with OS-level filesystem permissions. Domain checks inspect declared arguments and should be paired with network controls. Redaction remains best-effort.

Do not put real secrets in policy examples, demos, or tests.