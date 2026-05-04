import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import type { AttackChainDetector } from "../attackChain/detector.js";
import { evaluatePolicy } from "../policy/evaluator.js";
import { appendAuditReceipt, createAuditReceipt, readLastReceiptHash } from "../receipt/receipt.js";
import { redactPii, scanPii } from "../scan/pii.js";
import { redactSecrets, scanSecrets } from "../scan/secrets.js";
import type { AuditReceipt, CapabilityGraph, PolicyDecision, PolicyDocument } from "../types.js";
import { isToolCallRequest, makeJsonRpcError, parseJsonRpcLine, stringifyJsonRpc } from "./jsonRpc.js";
import { getToolCallParams } from "./mcpMessages.js";

export interface ProxyDecisionResult {
  action: "forward" | "respond";
  line: string;
  decision?: PolicyDecision;
  receipt?: AuditReceipt;
}

export interface HandleJsonRpcLineOptions {
  policy: PolicyDocument;
  graph?: CapabilityGraph;
  auditLogPath?: string;
  sessionId?: string;
  agent?: string;
  server?: string;
  interactive?: boolean;
  approve?: (decision: PolicyDecision) => Promise<boolean> | boolean;
  attackChainDetector?: AttackChainDetector;
}

export async function handleJsonRpcLine(line: string, options: HandleJsonRpcLineOptions): Promise<ProxyDecisionResult> {
  let message;
  try {
    message = parseJsonRpcLine(line);
  } catch (error) {
    return {
      action: "respond",
      line: stringifyJsonRpc(makeJsonRpcError(null, `Invalid JSON-RPC; failing closed: ${error instanceof Error ? error.message : String(error)}`, -32700))
    };
  }

  if (!isToolCallRequest(message)) {
    return { action: "forward", line };
  }

  try {
    const params = getToolCallParams(message);
    const node = options.graph?.nodes.find((candidate) => candidate.tool === params.name && (!options.server || candidate.server === options.server || !candidate.server));
    let decision = evaluatePolicy(options.policy, {
      tool: params.name,
      server: options.server ?? node?.server,
      arguments: params.arguments,
      capabilityNode: node,
      session_id: options.sessionId,
      agent: options.agent
    });

    if (node && decision.decision !== "block" && options.attackChainDetector) {
      const attackDecision = options.attackChainDetector.evaluateCall({
        session_id: options.sessionId ?? "default",
        tool: params.name,
        server: options.server ?? node.server,
        capabilities: node.capabilities,
        data_sensitivity: node.data_sensitivity,
        arguments: params.arguments
      });
      if (attackDecision.decision === "block") {
        decision = {
          ...decision,
          decision: "block",
          reason: attackDecision.reason,
          required_controls: [...new Set([...decision.required_controls, "attack_chain_block"])].sort()
        };
      } else if (attackDecision.decision === "warn" && decision.decision === "allow") {
        decision = {
          ...decision,
          decision: "warn",
          reason: attackDecision.reason,
          required_controls: [...new Set([...decision.required_controls, "attack_chain_review"])].sort()
        };
      }
    }

    if (decision.decision === "require_approval") {
      const approved = options.interactive && options.approve ? await options.approve(decision) : false;
      if (!approved) {
        decision = {
          ...decision,
          decision: "block",
          reason: `Approval required but not granted: ${decision.reason}`
        };
      }
    }

    const receipt = createAuditReceipt({
      agent: options.agent,
      server: options.server ?? node?.server,
      tool: params.name,
      decision: decision.decision,
      matched_rules: decision.matched_rules,
      arguments: params.arguments,
      policy_hash: options.policy.policy_hash,
      session_id: options.sessionId ?? "default",
      previous_receipt_hash: options.auditLogPath ? readLastReceiptHash(options.auditLogPath) : undefined
    });

    if (options.auditLogPath) {
      appendAuditReceipt(options.auditLogPath, receipt);
    }

    const decisionWithReceipt = { ...decision, receipt };
    if (decision.decision === "block") {
      return {
        action: "respond",
        line: stringifyJsonRpc(
          makeJsonRpcError(message.id, `MCP CapaGate blocked tool call: ${decision.reason}`, -32001, {
            decision: decisionWithReceipt
          })
        ),
        decision: decisionWithReceipt,
        receipt
      };
    }

    return {
      action: "forward",
      line,
      decision: decisionWithReceipt,
      receipt
    };
  } catch (error) {
    return {
      action: "respond",
      line: stringifyJsonRpc(makeJsonRpcError(message.id, `MCP CapaGate failed closed: ${error instanceof Error ? error.message : String(error)}`, -32002))
    };
  }
}

export function redactResponseLine(line: string): string {
  const secretFindings = scanSecrets(line);
  const piiFindings = scanPii(line);
  if (secretFindings.length === 0 && piiFindings.length === 0) {
    return line;
  }
  return redactPii(redactSecrets(line));
}

export interface RunStdioProxyOptions extends HandleJsonRpcLineOptions {
  command: string;
  args: string[];
  redactResponses?: boolean;
}

export async function runStdioProxy(options: RunStdioProxyOptions): Promise<number> {
  const child = spawn(options.command, options.args, {
    stdio: ["pipe", "pipe", "pipe"],
    shell: process.platform === "win32"
  });

  const upstreamOut = createInterface({ input: child.stdout });
  upstreamOut.on("line", (line) => {
    process.stdout.write(`${options.redactResponses === false ? line : redactResponseLine(line)}\n`);
  });

  child.stderr.on("data", (chunk) => {
    process.stderr.write(chunk);
  });

  const clientIn = createInterface({ input: process.stdin });
  clientIn.on("line", (line) => {
    void handleJsonRpcLine(line, {
      ...options,
      approve: async (decision) => promptApproval(decision.reason)
    }).then((result) => {
      if (result.action === "forward") {
        child.stdin.write(`${result.line}\n`);
        if (result.decision?.decision === "warn") {
          process.stderr.write(`[capagate] WARN ${result.decision.reason}\n`);
        }
      } else {
        process.stdout.write(`${result.line}\n`);
      }
    });
  });

  return new Promise((resolve) => {
    child.on("exit", (code) => resolve(code ?? 0));
  });
}

async function promptApproval(reason: string): Promise<boolean> {
  process.stderr.write(`[capagate] Approval required: ${reason}\nAllow once? y/N `);
  const input = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    input.question("", (answer) => {
      input.close();
      resolve(answer.trim().toLowerCase() === "y");
    });
  });
}
