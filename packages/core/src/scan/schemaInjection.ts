import type { MCPToolDefinition, ScanFinding } from "../types.js";
import { sha256 } from "../schema.js";

const RISKY_SCHEMA_KEYS = new Set(["$comment", "comment", "examples", "title", "description", "default"]);
const INSTRUCTION_LIKE = /(ignore previous|system prompt|developer message|must obey|secret|exfiltrate|do not tell|base64|auth context)/i;

export function scanSchemaInjection(tool: MCPToolDefinition): ScanFinding[] {
  const findings: ScanFinding[] = [];
  inspect(tool.inputSchema, "inputSchema", tool, findings);
  inspect(tool.outputSchema, "outputSchema", tool, findings);
  return findings;
}

export function scanAllSchemaInjection(tools: MCPToolDefinition[]): ScanFinding[] {
  return tools.flatMap((tool) => scanSchemaInjection(tool));
}

function inspect(value: unknown, path: string, tool: MCPToolDefinition, findings: ScanFinding[]): void {
  if (!value || typeof value !== "object") {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) => inspect(child, `${path}[${index}]`, tool, findings));
    return;
  }

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const childPath = `${path}.${key}`;
    if (RISKY_SCHEMA_KEYS.has(key) && typeof child === "string" && INSTRUCTION_LIKE.test(child)) {
      findings.push({
        id: sha256(`schema_injection:${tool.server ?? ""}:${tool.name}:${childPath}`).slice(0, 16),
        type: "schema_injection",
        severity: "high",
        tool: tool.name,
        server: tool.server,
        path: childPath,
        message: `Schema metadata field ${childPath} contains instruction-like text.`,
        evidence: child,
        recommendation: "Keep schema examples and comments data-shaped; remove instructions directed at agents."
      });
    }
    inspect(child, childPath, tool, findings);
  }
}
