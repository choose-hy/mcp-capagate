import type { Capability, CapabilityEvidence, MCPToolDefinition } from "../types.js";
import { CAPABILITY_RULES, EXFILTRATION_SINK_CAPABILITIES } from "./taxonomy.js";

export interface ExtractionResult {
  capabilities: Capability[];
  evidence: CapabilityEvidence[];
  confidence: number;
  preconditions: string[];
  effects: string[];
}

export function extractCapabilities(tool: MCPToolDefinition): ExtractionResult {
  const fieldTexts = collectToolTexts(tool);
  const evidence: CapabilityEvidence[] = [];
  const capabilities = new Set<Capability>();
  const effects = new Set<string>();

  for (const item of fieldTexts) {
    for (const rule of CAPABILITY_RULES) {
      const match = item.text.match(rule.regex);
      if (match?.[0]) {
        capabilities.add(rule.capability);
        effects.add(rule.effect);
        evidence.push({
          capability: rule.capability,
          source: item.path,
          match: match[0],
          confidence: rule.confidence
        });
      }
    }
  }

  if (capabilities.has("credential_access") && hasAny(capabilities, EXFILTRATION_SINK_CAPABILITIES)) {
    capabilities.add("cross_system_exfiltration");
    effects.add("Could move secrets or credentials to an external sink.");
    evidence.push({
      capability: "cross_system_exfiltration",
      source: "derived",
      match: "credential_access + external sink",
      confidence: 0.9
    });
  }

  if (capabilities.has("private_data_access") && hasAny(capabilities, EXFILTRATION_SINK_CAPABILITIES)) {
    capabilities.add("cross_system_exfiltration");
    effects.add("Could move private data to an external sink.");
    evidence.push({
      capability: "cross_system_exfiltration",
      source: "derived",
      match: "private_data_access + external sink",
      confidence: 0.84
    });
  }

  if (capabilities.size === 0) {
    capabilities.add("unknown");
    effects.add("Unclear capability surface; fail-closed policy should treat this cautiously.");
    evidence.push({
      capability: "unknown",
      source: "derived",
      match: "no deterministic capability match",
      confidence: 0.45
    });
  }

  const confidence = Math.max(...evidence.map((item) => item.confidence), 0.45);
  return {
    capabilities: [...capabilities].sort(),
    evidence,
    confidence,
    preconditions: derivePreconditions(capabilities),
    effects: [...effects].sort()
  };
}

function hasAny(capabilities: Set<Capability>, wanted: Capability[]): boolean {
  return wanted.some((capability) => capabilities.has(capability));
}

function derivePreconditions(capabilities: Set<Capability>): string[] {
  const preconditions = new Set<string>();
  if (capabilities.has("financial_action")) {
    preconditions.add("Business confirmation and idempotency key should be present before execution.");
  }
  if (capabilities.has("shell_execution") || capabilities.has("execute_code")) {
    preconditions.add("Explicit operator approval should be required before command execution.");
  }
  if (capabilities.has("private_data_access") || capabilities.has("credential_access")) {
    preconditions.add("Caller must have least-privilege access to sensitive data.");
  }
  if (capabilities.has("external_network") || capabilities.has("send_message")) {
    preconditions.add("Destination should be allowlisted and response redaction should be enabled.");
  }
  return [...preconditions].sort();
}

function collectToolTexts(tool: MCPToolDefinition): Array<{ path: string; text: string }> {
  const texts: Array<{ path: string; text: string }> = [
    { path: "name", text: tool.name },
    { path: "description", text: tool.description }
  ];

  collectRecursiveStrings(tool.inputSchema, "inputSchema", texts);
  collectRecursiveStrings(tool.outputSchema, "outputSchema", texts);
  collectRecursiveStrings(tool.annotations, "annotations", texts);
  return texts.filter((item) => item.text.trim().length > 0);
}

function collectRecursiveStrings(value: unknown, path: string, out: Array<{ path: string; text: string }>): void {
  if (value === undefined || value === null) {
    return;
  }

  if (typeof value === "string") {
    out.push({ path, text: value });
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => collectRecursiveStrings(item, `${path}[${index}]`, out));
    return;
  }

  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      out.push({ path: `${path}.${key}`, text: key });
      collectRecursiveStrings(child, `${path}.${key}`, out);
    }
  }
}
