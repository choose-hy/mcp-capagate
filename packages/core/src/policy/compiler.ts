import type { Capability, CapabilityGraph, PolicyConstraints, PolicyDecisionName, PolicyDocument, PolicyRule } from "../types.js";
import { policyHashPayload, sha256 } from "../schema.js";
import { DEFAULT_POLICY_CONFIG } from "./defaultPolicies.js";

export interface CompilePolicyOptions {
  unknown_tool?: PolicyDecisionName;
  fail_closed?: boolean;
  redact_response?: boolean;
}

export function compilePolicy(graph: CapabilityGraph, options: CompilePolicyOptions = {}): PolicyDocument {
  const rules = graph.nodes.map((node, index): PolicyRule => {
    const decision = decisionForCapabilities(node.capabilities, node.risk_level);
    const constraints = constraintsForCapabilities(node.capabilities);
    return {
      id: `tool.${node.server ?? "local"}.${node.tool}`.replace(/[^a-zA-Z0-9_.-]/g, "_"),
      match: {
        tool: node.tool,
        server: node.server,
        capabilities: node.capabilities,
        risk_level: node.risk_level,
        data_sensitivity: node.data_sensitivity
      },
      decision,
      reason: reasonForDecision(decision, node.capabilities),
      constraints,
      controls: [...new Set([...node.required_controls, ...controlsForConstraints(constraints)])].sort(),
      priority: priorityForDecision(decision) + (100 - index)
    };
  });

  const withoutHash = {
    version: "0.1" as const,
    generated_at: new Date().toISOString(),
    defaults: {
      unknown_tool: options.unknown_tool ?? DEFAULT_POLICY_CONFIG.unknown_tool,
      fail_closed: options.fail_closed ?? DEFAULT_POLICY_CONFIG.fail_closed,
      redact_response: options.redact_response ?? DEFAULT_POLICY_CONFIG.redact_response
    },
    rules: rules.sort((a, b) => b.priority - a.priority)
  };

  return {
    ...withoutHash,
    policy_hash: sha256(policyHashPayload(withoutHash))
  };
}

export function decisionForCapabilities(capabilities: Capability[], riskLevel: string): PolicyDecisionName {
  const set = new Set(capabilities);
  if (
    set.has("shell_execution") ||
    set.has("execute_code") ||
    (set.has("credential_access") && (set.has("external_network") || set.has("send_message") || set.has("webhook_post"))) ||
    set.has("delete_data")
  ) {
    return "block";
  }

  if (
    set.has("financial_action") ||
    set.has("private_data_access") ||
    set.has("filesystem_write") ||
    set.has("database_write") ||
    set.has("write_data") ||
    set.has("send_message") ||
    set.has("external_network") ||
    set.has("webhook_post")
  ) {
    return "require_approval";
  }

  if (set.has("unknown") || riskLevel === "medium") {
    return "warn";
  }

  return "allow";
}

export function constraintsForCapabilities(capabilities: Capability[]): PolicyConstraints | undefined {
  const set = new Set(capabilities);
  const constraints: PolicyConstraints = {};

  if (set.has("filesystem_read")) {
    constraints.path_prefixes = ["./", "docs/", "examples/"];
  }

  if (set.has("financial_action")) {
    constraints.max_amount = 100;
    constraints.required_boolean_flags = ["confirmed"];
  }

  if (set.has("webhook_post")) {
    constraints.allowed_domains = [];
  }

  return Object.keys(constraints).length > 0 ? constraints : undefined;
}

function controlsForConstraints(constraints: PolicyConstraints | undefined): string[] {
  if (!constraints) {
    return [];
  }

  const controls = new Set<string>(["constraint_review"]);
  if (constraints.path_prefixes) {
    controls.add("path_allowlist");
  }
  if (constraints.allowed_domains || constraints.blocked_domains) {
    controls.add("destination_allowlist");
  }
  if (constraints.max_amount !== undefined || constraints.required_boolean_flags) {
    controls.add("business_confirmation");
  }
  return [...controls].sort();
}

function priorityForDecision(decision: PolicyDecisionName): number {
  switch (decision) {
    case "block":
      return 1000;
    case "require_approval":
      return 800;
    case "warn":
      return 500;
    case "allow":
      return 100;
  }
}

function reasonForDecision(decision: PolicyDecisionName, capabilities: Capability[]): string {
  const capabilityList = capabilities.join(", ");
  switch (decision) {
    case "block":
      return `Blocked by least-privilege policy because capabilities include ${capabilityList}.`;
    case "require_approval":
      return `Requires approval because capabilities include ${capabilityList}.`;
    case "warn":
      return `Allowed with warning because capability confidence or risk needs review: ${capabilityList}.`;
    case "allow":
      return `Allowed because tool appears read-only and low risk: ${capabilityList}.`;
  }
}