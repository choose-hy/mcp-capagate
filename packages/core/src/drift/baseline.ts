import type { CapabilityGraph } from "../types.js";
import { sha256 } from "../schema.js";
import { diffCapabilityGraphs, driftReportShouldFail, type DriftFailThreshold } from "./diff.js";

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

export function unwrapBaselineGraph(value: unknown): CapabilityGraph {
  const maybeRecord = value as { graph?: CapabilityGraph };
  return maybeRecord.graph ?? (value as CapabilityGraph);
}

export function verifyBaselineDrift(baseline: unknown, current: unknown, failOn: DriftFailThreshold = "high") {
  const baselineGraph = unwrapBaselineGraph(baseline);
  const currentGraph = unwrapBaselineGraph(current);
  const report = diffCapabilityGraphs(baselineGraph, currentGraph);
  return {
    ...report,
    should_fail: driftReportShouldFail(report, failOn),
    fail_on: failOn
  };
}
