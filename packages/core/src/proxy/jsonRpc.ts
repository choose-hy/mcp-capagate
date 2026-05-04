export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse | Record<string, unknown>;

export function parseJsonRpcLine(line: string): JsonRpcMessage {
  const parsed = JSON.parse(line) as JsonRpcMessage;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("JSON-RPC line must parse to an object.");
  }
  return parsed;
}

export function isJsonRpcRequest(message: JsonRpcMessage): message is JsonRpcRequest {
  return (message as JsonRpcRequest).jsonrpc === "2.0" && typeof (message as JsonRpcRequest).method === "string";
}

export function isToolCallRequest(message: JsonRpcMessage): message is JsonRpcRequest {
  return isJsonRpcRequest(message) && message.method === "tools/call";
}

export function makeJsonRpcError(id: JsonRpcId | undefined, message: string, code = -32000, data?: unknown): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: {
      code,
      message,
      data
    }
  };
}

export function makeJsonRpcResult(id: JsonRpcId | undefined, result: unknown): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    result
  };
}

export function stringifyJsonRpc(message: JsonRpcMessage): string {
  return JSON.stringify(message);
}
