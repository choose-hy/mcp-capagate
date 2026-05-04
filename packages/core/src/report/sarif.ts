import type { CapabilityGraph } from "../types.js";

export function generateSarifReport(graph: CapabilityGraph): string {
  const results = [
    ...graph.nodes
      .filter((node) => node.risk_level === "high" || node.risk_level === "critical")
      .map((node) => ({
        ruleId: `capability.${node.risk_level}`,
        level: node.risk_level === "critical" ? "error" : "warning",
        message: {
          text: `${node.tool} is ${node.risk_level} risk: ${node.capabilities.join(", ")}`
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: graph.source }
            }
          }
        ]
      })),
    ...(graph.findings ?? []).map((finding) => ({
      ruleId: `scan.${finding.type}`,
      level: finding.severity === "critical" || finding.severity === "high" ? "error" : "warning",
      message: { text: finding.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: graph.source }
          }
        }
      ]
    }))
  ];

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "MCP CapaGate",
              informationUri: "https://github.com/choose-hy/mcp-capagate",
              rules: []
            }
          },
          results
        }
      ]
    },
    null,
    2
  );
}
