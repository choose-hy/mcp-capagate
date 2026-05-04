import type { MCPToolDefinition, ScanFinding } from "../types.js";
import { sha256 } from "../schema.js";

const POISONING_PATTERNS = [
  /ignore previous instructions/i,
  /hidden instruction/i,
  /system prompt/i,
  /developer message/i,
  /exfiltrate/i,
  /send secrets/i,
  /include auth context/i,
  /base64 encode/i,
  /do not tell the user/i,
  /<IMPORTANT>/i,
  /\[CRITICAL]/i,
  /markdown hidden instructions/i,
  /prompt injection/i
];

export function scanToolPoisoning(tool: MCPToolDefinition): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const item of collectStrings(tool)) {
    const pattern = POISONING_PATTERNS.find((candidate) => candidate.test(item.text));
    if (!pattern) {
      continue;
    }
    findings.push({
      id: sha256(`tool_poisoning:${tool.server ?? ""}:${tool.name}:${item.path}:${pattern.source}`).slice(0, 16),
      type: "tool_poisoning",
      severity: "high",
      tool: tool.name,
      server: tool.server,
      path: item.path,
      message: `Tool metadata contains prompt-injection-like text at ${item.path}.`,
      evidence: preview(item.text),
      recommendation: "Remove instruction-like text from tool metadata and keep descriptions declarative."
    });
  }
  return findings;
}

export function scanAllToolPoisoning(tools: MCPToolDefinition[]): ScanFinding[] {
  return tools.flatMap((tool) => scanToolPoisoning(tool));
}

function collectStrings(value: unknown, path = "tool"): Array<{ path: string; text: string }> {
  if (typeof value === "string") {
    return [{ path, text: value }];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectStrings(item, `${path}[${index}]`));
  }
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => collectStrings(child, `${path}.${key}`));
  }
  return [];
}

function preview(text: string): string {
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
}
