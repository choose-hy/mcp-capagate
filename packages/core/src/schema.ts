import { createHash } from "node:crypto";
import { z } from "zod";
import type { CapabilityGraph, MCPToolDefinition, PolicyConstraints, PolicyDocument } from "./types.js";

const recordSchema = z.record(z.string(), z.unknown());

export const BlockedArgumentPatternSchema = z.object({
  path: z.string().min(1),
  pattern: z.string().min(1),
  reason: z.string().min(1)
});

export const PolicyConstraintsSchema: z.ZodType<PolicyConstraints> = z
  .object({
    path_prefixes: z.array(z.string()).optional(),
    allowed_domains: z.array(z.string()).optional(),
    blocked_domains: z.array(z.string()).optional(),
    max_amount: z.number().nonnegative().optional(),
    required_boolean_flags: z.array(z.string()).optional(),
    blocked_argument_patterns: z.array(BlockedArgumentPatternSchema).optional(),
    required_argument_paths: z.array(z.string()).optional(),
    blocked_argument_paths: z.array(z.string()).optional()
  })
  .strict();

export const MCPToolDefinitionSchema = z
  .object({
    name: z.string().min(1),
    description: z.string().optional().default(""),
    inputSchema: recordSchema.optional(),
    input_schema: recordSchema.optional(),
    outputSchema: recordSchema.optional(),
    output_schema: recordSchema.optional(),
    annotations: recordSchema.optional(),
    server: z.string().optional()
  })
  .passthrough()
  .transform((value): MCPToolDefinition => ({
    name: value.name,
    description: value.description ?? "",
    inputSchema: value.inputSchema ?? value.input_schema ?? { type: "object", properties: {} },
    outputSchema: value.outputSchema ?? value.output_schema,
    annotations: value.annotations,
    server: value.server
  }));

export const MCPToolDefinitionArraySchema = z.array(MCPToolDefinitionSchema);

export const CapabilityGraphSchema: z.ZodType<CapabilityGraph> = z.any();
export const PolicyDocumentSchema: z.ZodType<PolicyDocument> = z.any();

export function normalizeToolDefinitions(raw: unknown, server?: string): MCPToolDefinition[] {
  const candidate = unwrapTools(raw);
  const parsed = MCPToolDefinitionArraySchema.parse(candidate);
  return parsed.map((tool) => ({
    ...tool,
    server: tool.server ?? server
  }));
}

function unwrapTools(raw: unknown): unknown {
  if (Array.isArray(raw)) {
    return raw;
  }

  if (raw && typeof raw === "object") {
    const object = raw as Record<string, unknown>;
    if (Array.isArray(object.tools)) {
      return object.tools;
    }

    if (object.result && typeof object.result === "object") {
      const result = object.result as Record<string, unknown>;
      if (Array.isArray(result.tools)) {
        return result.tools;
      }
    }
  }

  throw new Error("Expected MCP tools as an array, { tools }, or tools/list { result: { tools } } response.");
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  const object = value as Record<string, unknown>;
  const entries = Object.keys(object)
    .filter((key) => object[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`);
  return `{${entries.join(",")}}`;
}

export function sha256(value: string | unknown): string {
  const payload = typeof value === "string" ? value : stableStringify(value);
  return createHash("sha256").update(payload).digest("hex");
}

export function graphHashPayload(graph: Omit<CapabilityGraph, "graph_hash">): unknown {
  const { generated_at: _generatedAt, ...stable } = graph;
  return stable;
}

export function policyHashPayload(policy: Omit<PolicyDocument, "policy_hash">): unknown {
  const { generated_at: _generatedAt, ...stable } = policy;
  return stable;
}
