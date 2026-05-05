# MCP CapaGate GitHub Action

This package documents the repository-root composite action in `action.yml`.

```yaml
      - uses: choose-hy/mcp-capagate@v0.2.0
  with:
    config: capagate.yaml
    fail-on: high
    report-dir: reports
```

The action installs dependencies, builds the TypeScript workspace, runs `capagate scan`, compiles `capagate.policy.yaml`, generates Markdown/HTML/SARIF reports, writes the Markdown report to the GitHub step summary, and fails the job when the configured risk threshold is reached.
