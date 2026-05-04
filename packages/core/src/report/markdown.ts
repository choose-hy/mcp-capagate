import type { AuditReceipt, CapabilityGraph, DriftReport, PolicyDocument, ScanFinding } from "../types.js";

export interface MarkdownReportInput {
  graph: CapabilityGraph;
  policy?: PolicyDocument;
  audit?: AuditReceipt[];
  drift?: DriftReport;
  attackFindings?: ScanFinding[];
}

export function generateMarkdownReport(input: MarkdownReportInput): string {
  const { graph, policy, audit = [], drift, attackFindings = [] } = input;
  const criticalRisks = graph.nodes.filter((node) => node.risk_level === "critical");
  const findings = [...(graph.findings ?? []), ...attackFindings];

  return [
    "# MCP CapaGate Security Report",
    "",
    "## Security posture summary",
    `- Tools analyzed: ${graph.summary.tool_count}`,
    `- Critical tools: ${graph.summary.risk_counts.critical}`,
    `- High tools: ${graph.summary.risk_counts.high}`,
    `- Findings: ${findings.length}`,
    `- Graph hash: \`${graph.graph_hash}\``,
    "",
    "## Capability graph summary",
    `- Nodes: ${graph.summary.node_count}`,
    `- Edges: ${graph.summary.edge_count}`,
    `- Top capabilities: ${Object.entries(graph.summary.capability_counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([capability, count]) => `${capability}=${count}`)
      .join(", ") || "none"}`,
    "",
    "## Tool risk matrix",
    "| Tool | Server | Risk | Sensitivity | Capabilities |",
    "| --- | --- | --- | --- | --- |",
    ...graph.nodes.map((node) => `| ${node.tool} | ${node.server ?? "local"} | ${node.risk_level} | ${node.data_sensitivity} | ${node.capabilities.join(", ")} |`),
    "",
    "## Top critical risks",
    ...(criticalRisks.length
      ? criticalRisks.map((node) => `- **${node.tool}**: ${node.effects.join(" ")}`)
      : ["- No critical capability nodes detected."]),
    "",
    "## Scan findings",
    ...(findings.length
      ? findings.map((finding) => `- [${finding.severity}] ${finding.type}${finding.tool ? ` in ${finding.tool}` : ""}: ${finding.message}`)
      : ["- No scanner findings recorded."]),
    "",
    "## Policy decisions",
    ...(policy
      ? policy.rules.slice(0, 20).map((rule) => `- **${rule.match.tool ?? "*"}**: ${rule.decision.toUpperCase()} - ${rule.reason}`)
      : ["- Policy was not provided for this report."]),
    "",
    "## Drift findings",
    ...(drift?.findings.length
      ? drift.findings.map((finding) => `- [${finding.severity}] ${finding.message}`)
      : ["- No drift report provided or no drift detected."]),
    "",
    "## Attack-chain findings",
    ...(attackFindings.length ? attackFindings.map((finding) => `- [${finding.severity}] ${finding.message}`) : ["- No attack-chain findings recorded."]),
    "",
    "## Audit timeline",
    ...(audit.length
      ? audit.map((receipt) => `- ${receipt.timestamp} ${receipt.tool}: ${receipt.decision.toUpperCase()} (\`${receipt.receipt_hash.slice(0, 12)}\`)`)
      : ["- No audit receipts recorded."]),
    "",
    "## Recommended fixes",
    ...recommendedFixes(graph, findings),
    "",
    "## Product-facing summary",
    "MCP CapaGate maps every discovered MCP tool into a deterministic capability graph, then turns that graph into policy decisions that can be enforced before tool calls execute.",
    "",
    "## Developer-facing remediation",
    "Review critical capability nodes first, remove instruction-like metadata from tool schemas, require approval for write or external-message tools, and keep baselines under version control to detect drift."
  ].join("\n");
}

function recommendedFixes(graph: CapabilityGraph, findings: ScanFinding[]): string[] {
  const fixes = new Set<string>();
  for (const node of graph.nodes) {
    if (node.risk_level === "critical") {
      fixes.add(`- Put \`${node.tool}\` behind BLOCK or REQUIRE_APPROVAL until controls are configured.`);
    }
  }
  for (const finding of findings) {
    if (finding.recommendation) {
      fixes.add(`- ${finding.recommendation}`);
    }
  }
  if (fixes.size === 0) {
    fixes.add("- Keep the generated policy and baseline under review as tools evolve.");
  }
  return [...fixes];
}
