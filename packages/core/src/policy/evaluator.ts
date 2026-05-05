import type { Capability, DataSensitivity, PolicyDecision, PolicyDocument, PolicyRule, RiskLevel, ToolCallContext } from "../types.js";
import { evaluateConstraints } from "./constraints.js";

export function evaluatePolicy(policy: PolicyDocument, context: ToolCallContext): PolicyDecision {
  try {
    const matched = policy.rules
      .filter((rule) => matchesRule(rule, context))
      .sort((a, b) => b.priority - a.priority);

    const rule = matched[0];
    if (!rule) {
      return {
        decision: policy.defaults.unknown_tool,
        reason: `Unknown tool ${context.tool}; default is ${policy.defaults.unknown_tool}.`,
        matched_rules: [],
        required_controls: policy.defaults.fail_closed ? ["fail_closed_review"] : [],
        redact_response: policy.defaults.redact_response
      };
    }

    const requiredControls = [...new Set(matched.flatMap((item) => item.controls))].sort();
    const redactResponse = policy.defaults.redact_response || rule.controls.some((control) => control.includes("redaction"));
    const constraintEvaluation = evaluateConstraints(rule.constraints, context.arguments);

    if (constraintEvaluation.status === "fail") {
      const firstFinding = constraintEvaluation.findings[0];
      return {
        decision: "block",
        reason: `Policy constraint failed for ${context.tool}: ${firstFinding?.reason ?? "constraint evaluation failed closed"}`,
        matched_rules: matched.map((item) => item.id),
        required_controls: [...new Set([...requiredControls, "constraint_review"])].sort(),
        redact_response: redactResponse,
        constraint_findings: constraintEvaluation.findings
      };
    }

    return {
      decision: rule.decision,
      reason: rule.reason,
      matched_rules: matched.map((item) => item.id),
      required_controls: requiredControls,
      redact_response: redactResponse,
      constraint_findings: constraintEvaluation.findings
    };
  } catch (error) {
    return {
      decision: "block",
      reason: `Policy evaluation failed closed: ${error instanceof Error ? error.message : String(error)}`,
      matched_rules: [],
      required_controls: ["fail_closed_review"],
      redact_response: true
    };
  }
}

function matchesRule(rule: PolicyRule, context: ToolCallContext): boolean {
  if (rule.match.tool && rule.match.tool !== context.tool) {
    return false;
  }

  if (rule.match.server && context.server && rule.match.server !== context.server) {
    return false;
  }

  const node = context.capabilityNode;
  if (!node) {
    return true;
  }

  if (rule.match.capabilities && !containsAll(node.capabilities, rule.match.capabilities)) {
    return false;
  }

  if (rule.match.risk_level && !matchesScalarOrArray(node.risk_level, rule.match.risk_level)) {
    return false;
  }

  if (rule.match.data_sensitivity && !matchesScalarOrArray(node.data_sensitivity, rule.match.data_sensitivity)) {
    return false;
  }

  return true;
}

function containsAll(actual: Capability[], expected: Capability[]): boolean {
  const actualSet = new Set(actual);
  return expected.every((item) => actualSet.has(item));
}

function matchesScalarOrArray<T extends RiskLevel | DataSensitivity>(actual: T, expected: T | T[]): boolean {
  return Array.isArray(expected) ? expected.includes(actual) : actual === expected;
}