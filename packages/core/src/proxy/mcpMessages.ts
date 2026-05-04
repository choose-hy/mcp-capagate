import type { JsonRpcRequest } from "./jsonRpc.js";

export interface ToolCallParams {
  name: string;
  arguments?: unknown;
  _meta?: Record<string, unknown>;
}

export function getToolCallParams(request: JsonRpcRequest): ToolCallParams {
  const params = request.params;
  if (!params || typeof params !== "object") {
    throw new Error("tools/call params must be an object.");
  }
  const object = params as Record<string, unknown>;
  if (typeof object.name !== "string" || object.name.length === 0) {
    throw new Error("tools/call params.name must be a non-empty string.");
  }
  return {
    name: object.name,
    arguments: object.arguments,
    _meta: object._meta as Record<string, unknown> | undefined
  };
}
