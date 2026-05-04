import type { CapabilityGraph } from "../types.js";
import { sha256 } from "../schema.js";

export interface BaselineRecord {
  created_at: string;
  graph_hash: string;
  graph: CapabilityGraph;
}

export function createBaseline(graph: CapabilityGraph): BaselineRecord {
  return {
    created_at: new Date().toISOString(),
    graph_hash: graph.graph_hash,
    graph
  };
}

export function baselineHash(graph: CapabilityGraph): string {
  return sha256({
    tools: graph.tools,
    nodes: graph.nodes,
    edges: graph.edges
  });
}
