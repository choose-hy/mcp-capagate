import { evaluatePolicy } from "../policy/evaluator.js";
import type { CapabilityGraph, PolicyDecision, PolicyDocument } from "../types.js";

export interface HttpToolCall {
  tool: string;
  arguments?: unknown;
  server?: string;
  session_id?: string;
}

export function evaluateHttpToolCall(policy: PolicyDocument, graph: CapabilityGraph | undefined, call: HttpToolCall): PolicyDecision {
  const node = graph?.nodes.find((candidate) => candidate.tool === call.tool && (!call.server || candidate.server === call.server));
  return evaluatePolicy(policy, {
    tool: call.tool,
    server: call.server ?? node?.server,
    arguments: call.arguments,
    capabilityNode: node,
    session_id: call.session_id
  });
}
