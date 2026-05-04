import type { Capability, CapabilityEdge, CapabilityGraph, CapabilityNode, FindingSeverity, MCPToolDefinition, RiskLevel, ScanFinding } from "../types.js";
import { graphHashPayload, sha256 } from "../schema.js";
import { extractCapabilities } from "./extractor.js";
import { EXFILTRATION_SINK_CAPABILITIES, WRITE_CAPABILITIES } from "./taxonomy.js";
import { scoreCapabilityNode } from "./riskScorer.js";

export function buildCapabilityGraph(tools: MCPToolDefinition[], source: string, findings: ScanFinding[] = []): CapabilityGraph {
  const nodes = tools.map((tool) => {
    const extracted = extractCapabilities(tool);
    return scoreCapabilityNode({
      id: nodeId(tool),
      tool: tool.name,
      server: tool.server,
      capabilities: extracted.capabilities,
      preconditions: extracted.preconditions,
      effects: extracted.effects,
      evidence: extracted.evidence,
      confidence: extracted.confidence
    });
  });

  const edges = buildEdges(nodes);
  const summary = summarizeGraph(tools, nodes, edges, findings);
  const withoutHash = {
    generated_at: new Date().toISOString(),
    source,
    tools,
    nodes,
    edges,
    summary,
    findings
  };

  return {
    ...withoutHash,
    graph_hash: sha256(graphHashPayload(withoutHash))
  };
}

export function nodeId(tool: Pick<MCPToolDefinition, "name" | "server">): string {
  return sha256(`${tool.server ?? "local"}:${tool.name}`).slice(0, 16);
}

function buildEdges(nodes: CapabilityNode[]): CapabilityEdge[] {
  const edges: CapabilityEdge[] = [];

  for (const node of nodes) {
    const caps = new Set(node.capabilities);
    if (hasAny(caps, WRITE_CAPABILITIES)) {
      edges.push(edge(node.id, node.id, "can_mutate_state", `${node.tool} can mutate state.`, node.risk_level));
    }
    if (caps.has("shell_execution") || caps.has("execute_code")) {
      edges.push(edge(node.id, node.id, "can_execute_code", `${node.tool} can execute code or shell commands.`, "critical"));
    }
    if (caps.has("private_data_access") || caps.has("credential_access")) {
      edges.push(edge(node.id, node.id, "can_access_private_data", `${node.tool} can access sensitive data.`, node.risk_level));
    }
  }

  for (const from of nodes) {
    const fromCaps = new Set(from.capabilities);
    const readsSensitive = fromCaps.has("private_data_access") || fromCaps.has("credential_access") || fromCaps.has("filesystem_read") || fromCaps.has("database_query");
    for (const to of nodes) {
      if (from.id === to.id) {
        continue;
      }
      const toCaps = new Set(to.capabilities);
      if (readsSensitive && hasAny(toCaps, EXFILTRATION_SINK_CAPABILITIES)) {
        edges.push(edge(from.id, to.id, "can_read_then_send", `${from.tool} can read data before ${to.tool} sends externally.`, "high"));
        edges.push(edge(from.id, to.id, "can_exfiltrate_to", `${to.tool} is a possible exfiltration sink after ${from.tool}.`, "critical"));
      }
      if ((fromCaps.has("filesystem_write") || fromCaps.has("write_data")) && (toCaps.has("shell_execution") || toCaps.has("execute_code"))) {
        edges.push(edge(from.id, to.id, "potential_tool_chain", `${from.tool} followed by ${to.tool} resembles a persistence or execution chain.`, "high"));
      }
    }
  }

  const byTool = new Map<string, CapabilityNode[]>();
  for (const node of nodes) {
    const existing = byTool.get(node.tool) ?? [];
    existing.push(node);
    byTool.set(node.tool, existing);
  }
  for (const sameNameNodes of byTool.values()) {
    const servers = new Set(sameNameNodes.map((node) => node.server ?? "local"));
    if (sameNameNodes.length > 1 && servers.size > 1) {
      for (const from of sameNameNodes) {
        for (const to of sameNameNodes) {
          if (from.id !== to.id) {
            edges.push(edge(from.id, to.id, "potential_shadowing", `Tool name ${from.tool} appears on multiple servers.`, "medium"));
          }
        }
      }
    }
  }

  return dedupeEdges(edges);
}

function summarizeGraph(tools: MCPToolDefinition[], nodes: CapabilityNode[], edges: CapabilityEdge[], findings: ScanFinding[]) {
  const risk_counts: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const capability_counts: Partial<Record<Capability, number>> = {};
  const finding_counts: Partial<Record<FindingSeverity, number>> = {};

  for (const node of nodes) {
    risk_counts[node.risk_level] += 1;
    for (const capability of node.capabilities) {
      capability_counts[capability] = (capability_counts[capability] ?? 0) + 1;
    }
  }

  for (const finding of findings) {
    finding_counts[finding.severity] = (finding_counts[finding.severity] ?? 0) + 1;
  }

  return {
    tool_count: tools.length,
    node_count: nodes.length,
    edge_count: edges.length,
    risk_counts,
    capability_counts,
    finding_counts
  };
}

function edge(from: string, to: string, type: CapabilityEdge["type"], reason: string, risk_level: RiskLevel): CapabilityEdge {
  return {
    id: sha256(`${from}:${to}:${type}:${reason}`).slice(0, 16),
    from,
    to,
    type,
    reason,
    risk_level
  };
}

function hasAny(capabilities: Set<Capability>, wanted: Capability[]): boolean {
  return wanted.some((capability) => capabilities.has(capability));
}

function dedupeEdges(edges: CapabilityEdge[]): CapabilityEdge[] {
  const seen = new Set<string>();
  return edges.filter((edgeItem) => {
    const key = `${edgeItem.from}:${edgeItem.to}:${edgeItem.type}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
