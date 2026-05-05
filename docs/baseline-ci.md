# Baseline CI

Capability graph baselines let teams review MCP tool drift in pull requests.

The workflow is:

1. Discover or provide tools.
2. Scan tools into a capability graph.
3. Save the graph as a baseline.
4. Verify future scans against that baseline in CI.

## Save a Baseline

```bash
capagate scan --input examples/refund-server/tools.json --out reports/scan.json
capagate baseline save --scan reports/scan.json --out .capagate/baseline.json
```

The baseline record stores the graph hash and the full capability graph.

## Verify Drift

```bash
capagate baseline verify \
  --baseline .capagate/baseline.json \
  --current reports/scan.json \
  --fail-on high
```

`--fail-on` accepts:

- `medium`
- `high`
- `critical`

The command writes `reports/drift.json` by default and exits non-zero when drift
findings reach the configured threshold.

## GitHub Action

Use the `baseline` and `fail-on-drift` inputs to enforce drift in pull requests:

```yaml
- uses: choose-hy/mcp-capagate@v0.1.0
  with:
    config: capagate.yaml
    fail-on: high
    baseline: .capagate/baseline.json
    fail-on-drift: high
    report-dir: reports
```

When a baseline is configured, the action runs `capagate baseline verify`,
writes `reports/drift.json`, and appends a drift summary to the Markdown report
and GitHub step summary.

## Review Guidance

High-signal drift to review:

- new high or critical tools
- capability changes on existing tools
- risk increases
- schema changes that expose new sensitive inputs
- description changes that alter tool intent

CapaGate does not replace code review. Treat baseline drift as a structured
review queue for MCP tool risk.
