import type { MCPToolDefinition, ScanFinding } from "../types.js";
import { sha256 } from "../schema.js";

const HIDDEN_UNICODE_REGEX = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u;

export function hasHiddenUnicode(text: string): boolean {
  return HIDDEN_UNICODE_REGEX.test(text);
}

export function scanHiddenUnicode(tool: MCPToolDefinition): ScanFinding[] {
  return collectStrings(tool).flatMap((item) => {
    if (!hasHiddenUnicode(item.text)) {
      return [];
    }
    return [
      {
        id: sha256(`hidden_unicode:${tool.server ?? ""}:${tool.name}:${item.path}`).slice(0, 16),
        type: "hidden_unicode" as const,
        severity: "medium" as const,
        tool: tool.name,
        server: tool.server,
        path: item.path,
        message: `Hidden Unicode or unusual control characters detected at ${item.path}.`,
        evidence: item.text.replace(HIDDEN_UNICODE_REGEX, "[hidden-char]"),
        recommendation: "Review and normalize Unicode in tool names, descriptions, and schemas."
      }
    ];
  });
}

export function scanAllHiddenUnicode(tools: MCPToolDefinition[]): ScanFinding[] {
  return tools.flatMap((tool) => scanHiddenUnicode(tool));
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
