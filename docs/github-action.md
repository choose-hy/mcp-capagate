# GitHub Action

Use the composite action to scan MCP tool definitions in CI.

```yaml
name: MCP CapaGate
on:
  pull_request:
jobs:
  capagate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: choose-hy/mcp-capagate@v0.1.0
        with:
          config: capagate.yaml
          fail-on: high
          report-dir: reports
```

The action runs:

- `pnpm install --frozen-lockfile`
- `pnpm build`
- `capagate scan`
- `capagate policy`
- `capagate report`

It writes the Markdown report to the GitHub step summary and fails when the configured threshold is reached.

## Baseline Drift

To enforce capability graph drift, pass a saved baseline:

```yaml
- uses: choose-hy/mcp-capagate@v0.1.0
  with:
    config: capagate.yaml
    fail-on: high
    baseline: .capagate/baseline.json
    fail-on-drift: high
    report-dir: reports
```

When `baseline` is set, the action also runs `capagate baseline verify`,
writes `reports/drift.json`, and appends a drift summary to the Markdown report.
