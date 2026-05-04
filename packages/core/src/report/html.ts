import type { AuditReceipt, CapabilityGraph, DriftReport, PolicyDocument, ScanFinding } from "../types.js";
import { generateMarkdownReport } from "./markdown.js";

export interface HtmlReportInput {
  graph: CapabilityGraph;
  policy?: PolicyDocument;
  audit?: AuditReceipt[];
  drift?: DriftReport;
  attackFindings?: ScanFinding[];
}

export function generateHtmlReport(input: HtmlReportInput): string {
  const markdown = generateMarkdownReport(input);
  const rows = input.graph.nodes
    .map(
      (node) =>
        `<tr><td>${escapeHtml(node.tool)}</td><td>${escapeHtml(node.server ?? "local")}</td><td><span class="risk ${node.risk_level}">${node.risk_level}</span></td><td>${escapeHtml(node.data_sensitivity)}</td><td>${escapeHtml(node.capabilities.join(", "))}</td></tr>`
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCP CapaGate Report</title>
  <style>
    :root { color-scheme: light dark; --bg: #fbfcfe; --text: #17202a; --muted: #637083; --line: #dce3ea; --panel: #ffffff; --accent: #0f766e; }
    body { margin: 0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); }
    header { padding: 32px clamp(20px, 5vw, 64px); border-bottom: 1px solid var(--line); background: #eef7f4; }
    main { max-width: 1120px; margin: 0 auto; padding: 28px 20px 56px; }
    h1 { margin: 0 0 8px; font-size: 32px; letter-spacing: 0; }
    h2 { margin-top: 32px; font-size: 20px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 20px; }
    .metric { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    .metric strong { display: block; font-size: 24px; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    th, td { text-align: left; border-bottom: 1px solid var(--line); padding: 10px 12px; vertical-align: top; }
    th { background: #f3f7fa; color: var(--muted); font-size: 13px; }
    .risk { font-weight: 700; text-transform: uppercase; font-size: 12px; }
    .critical { color: #b42318; } .high { color: #b54708; } .medium { color: #8a6f00; } .low { color: #067647; }
    pre { white-space: pre-wrap; background: #101828; color: #f2f4f7; padding: 16px; border-radius: 8px; overflow: auto; }
  </style>
</head>
<body>
  <header>
    <h1>MCP CapaGate Security Report</h1>
    <p>Capability-aware policy compiler and runtime firewall for MCP tool calls.</p>
    <div class="summary">
      <div class="metric"><span>Tools</span><strong>${input.graph.summary.tool_count}</strong></div>
      <div class="metric"><span>Critical</span><strong>${input.graph.summary.risk_counts.critical}</strong></div>
      <div class="metric"><span>High</span><strong>${input.graph.summary.risk_counts.high}</strong></div>
      <div class="metric"><span>Edges</span><strong>${input.graph.summary.edge_count}</strong></div>
    </div>
  </header>
  <main>
    <h2>Tool Risk Matrix</h2>
    <table><thead><tr><th>Tool</th><th>Server</th><th>Risk</th><th>Sensitivity</th><th>Capabilities</th></tr></thead><tbody>${rows}</tbody></table>
    <h2>Full Markdown Report</h2>
    <pre>${escapeHtml(markdown)}</pre>
  </main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}
