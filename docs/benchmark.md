# MCP Tool Risk Benchmark

MCP CapaGate includes a deterministic benchmark suite for measuring MCP tool
risk detection. The benchmark is designed to make capability extraction, policy
decisions, scanner findings, drift checks, and attack-chain detection visible
and repeatable.

It is not a machine-learning benchmark and does not require training data,
fine-tuning, proprietary data, telemetry, or an LLM API key.

## Run

```bash
capagate benchmark \
  --suite benchmarks/tool-risk-suite \
  --out reports/benchmark.json \
  --markdown reports/benchmark.md
```

The JSON report contains per-scenario results and aggregate metrics. The
Markdown report is intended for CI artifacts and pull request review.

## Scenario List

The initial suite covers:

1. `safe_read_only`
2. `private_data_access`
3. `credential_access`
4. `shell_execution`
5. `financial_action`
6. `external_exfiltration_sink`
7. `prompt_injection_description`
8. `hidden_unicode_description`
9. `schema_injection`
10. `tool_shadowing`
11. `schema_drift_low_to_high`
12. `secret_read_then_external_send`
13. `filesystem_write_then_shell`
14. `ambiguous_unknown_tool`

Each fixture contains:

- `tools.json`: synthetic MCP-like tool definitions
- `expected.json`: expected capabilities, risk, policy decision, scanner
  findings, drift findings, or attack-chain result

## Metrics

The benchmark computes:

- scenario pass rate
- capability match rate
- policy decision match rate
- scanner finding match rate
- false positive count when no scanner findings were expected
- false negative count for failed expected checks

## What This Measures

The suite measures deterministic CapaGate behavior:

- tool schema to capability graph mapping
- least-privilege policy compiler decisions
- scanner findings for prompt injection, hidden Unicode, schema injection,
  tool shadowing, and risky capabilities
- baseline drift from low-risk to high-risk tools
- attack-chain detection for sensitive reads followed by external sinks and
  filesystem writes followed by shell execution

## Limitations

The benchmark uses synthetic fixtures. It is intended to validate method
coverage and regressions, not to claim exhaustive detection of all MCP threats.
Capability extraction remains rule-based, so results can include false
positives or false negatives when real tools use ambiguous names or unusual
schemas. Probe-mode MCP discovery and runtime enforcement should be tested
separately with real server integrations.
