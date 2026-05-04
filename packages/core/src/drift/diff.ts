import type { CapabilityGraph, CapabilityNode, DriftFinding, DriftReport, FindingSeverity, RiskLevel } from "../types.js";
import { sha256 } from "../schema.js";

const riskRank: Record<RiskLevel, number> = { low: 1, medium: 2, high: 3, critical: 4 };

export function diffCapabilityGraphs(baseline: CapabilityGraph, current: CapabilityGraph): DriftReport {
  const findings: DriftFinding[] = [];
  const before = indexNodes(baseline.nodes);
  const after = indexNodes(current.nodes);

  for (const [key, node] of after) {
    const old = before.get(key);
    if (!old) {
      findings.push({
        id: sha256(`new_tool:${key}`).slice(0, 16),
        type: "new_tool",
        severity: severityForRisk(node.risk_level),
        tool: node.tool,
        server: node.server,
        message: `New tool ${node.tool} introduced with ${node.risk_level} risk.`,
        after: node
      });
      continue;
    }

    if (old.risk_level !== node.risk_level) {
      findings.push({
        id: sha256(`risk_change:${key}:${old.risk_level}:${node.risk_level}`).slice(0, 16),
        type: "risk_change",
        severity: severityForRisk(node.risk_level),
        tool: node.tool,
        server: node.server,
        message: `Risk changed from ${old.risk_level} to ${node.risk_level}.`,
        before: old.risk_level,
        after: node.risk_level
      });
    }

    if (old.capabilities.join(",") !== node.capabilities.join(",")) {
      findings.push({
        id: sha256(`capability_change:${key}`).slice(0, 16),
        type: "capability_change",
        severity: riskRank[node.risk_level] >= 3 ? "high" : "medium",
        tool: node.tool,
        server: node.server,
        message: `Capabilities changed for ${node.tool}.`,
        before: old.capabilities,
        after: node.capabilities
      });
    }
  }

  for (const [key, node] of before) {
    if (!after.has(key)) {
      findings.push({
        id: sha256(`removed_tool:${key}`).slice(0, 16),
        type: "removed_tool",
        severity: "low",
        tool: node.tool,
        server: node.server,
        message: `Tool ${node.tool} was removed.`,
        before: node
      });
    }
  }

  for (const currentTool of current.tools) {
    const baseTool = baseline.tools.find((tool) => tool.name === currentTool.name && (tool.server ?? "local") === (currentTool.server ?? "local"));
    if (!baseTool) {
      continue;
    }
    if (baseTool.description !== currentTool.description) {
      findings.push({
        id: sha256(`description_change:${currentTool.server ?? ""}:${currentTool.name}`).slice(0, 16),
        type: "description_change",
        severity: "medium",
        tool: currentTool.name,
        server: currentTool.server,
        message: `Description changed for ${currentTool.name}.`,
        before: baseTool.description,
        after: currentTool.description
      });
    }
    if (sha256(baseTool.inputSchema) !== sha256(currentTool.inputSchema)) {
      findings.push({
        id: sha256(`schema_change:${currentTool.server ?? ""}:${currentTool.name}`).slice(0, 16),
        type: "schema_change",
        severity: "medium",
        tool: currentTool.name,
        server: currentTool.server,
        message: `Input schema changed for ${currentTool.name}.`
      });
    }
  }

  if (baseline.graph_hash !== current.graph_hash) {
    findings.push({
      id: sha256(`hash_change:${baseline.graph_hash}:${current.graph_hash}`).slice(0, 16),
      type: "hash_change",
      severity: "info",
      tool: "*",
      message: "Capability graph hash changed.",
      before: baseline.graph_hash,
      after: current.graph_hash
    });
  }

  return {
    generated_at: new Date().toISOString(),
    baseline_hash: baseline.graph_hash,
    current_hash: current.graph_hash,
    findings,
    should_fail: findings.some((finding) => finding.severity === "high" || finding.severity === "critical")
  };
}

function indexNodes(nodes: CapabilityNode[]): Map<string, CapabilityNode> {
  return new Map(nodes.map((node) => [`${node.server ?? "local"}:${node.tool}`, node]));
}

function severityForRisk(risk: RiskLevel): FindingSeverity {
  if (risk === "critical") {
    return "critical";
  }
  if (risk === "high") {
    return "high";
  }
  if (risk === "medium") {
    return "medium";
  }
  return "low";
}
