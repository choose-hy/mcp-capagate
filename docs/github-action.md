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
