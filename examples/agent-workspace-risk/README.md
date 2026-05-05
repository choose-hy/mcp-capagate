# Agent Workspace Risk Example

This is a synthetic MCP-like tool catalog for an AI agent workspace. It models a realistic product environment where one agent can read and write workspace files, look up customer profiles, issue billing refunds, send email, post webhooks, and run emergency shell diagnostics.

The fixture uses safe placeholder schemas only. It does not contain real secrets, real customer records, or live endpoints.

## What It Demonstrates

- read-only tools such as `read_file` may be allowed or warned depending on sensitivity
- private customer profile reads should require review and response redaction
- financial actions such as `issue_refund` should require approval or block in non-interactive automation
- `execute_shell` should block by default
- `send_email` and `post_webhook` are external sinks
- sensitive reads followed by email or webhook calls are attack-chain risks

## Scan

```bash
capagate scan --input examples/agent-workspace-risk/tools.json --out reports/agent-workspace-scan.json
```

## Compile Policy

```bash
capagate policy --input reports/agent-workspace-scan.json --out reports/agent-workspace-policy.yaml
```

## Generate Report

```bash
capagate report --scan reports/agent-workspace-scan.json --policy reports/agent-workspace-policy.yaml --html reports/agent-workspace.html --markdown reports/agent-workspace.md
```


## Constraint Policy Example

`policy-constraints.yaml` is an illustrative policy-as-code file for this scenario. It shows how to:

- allow `read_file` only under `./docs/`
- require `confirmed=true` for `issue_refund`
- block `issue_refund` when the amount is greater than `100`
- allow `send_email` only to `company.com`
- block webhook posts unless a destination host is explicitly allowlisted

The file is meant for review and adaptation. It is not generated output and it does not contain real secrets or live endpoints.
## Expected Decisions

Typical deterministic policy output should treat the tools roughly as follows:

- `read_file`: `ALLOW` or `WARN`, depending on inferred sensitivity
- `read_customer_profile`: `REQUIRE_APPROVAL`
- `update_customer_profile`: `REQUIRE_APPROVAL`
- `issue_refund`: `REQUIRE_APPROVAL` or `BLOCK` in non-interactive workflows
- `send_email`: `REQUIRE_APPROVAL`, and risky after private data reads
- `post_webhook`: `REQUIRE_APPROVAL`, and risky after private data reads
- `execute_shell`: `BLOCK`
- `delete_file`: `BLOCK`

## Why This Is Realistic

AI agent products often combine workspace access, CRM data, billing operations, and communication tools in one assistant. Each tool can be reasonable alone, but combinations create new risk: private data can flow to external sinks, write access can prepare persistence, and financial actions can mutate business state. CapaGate makes those capabilities explicit before the agent executes a tool call.