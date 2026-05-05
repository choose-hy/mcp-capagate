import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import type { AttackChainDetector } from "../attackChain/detector.js";
import { TaintTracker } from "../attackChain/taint.js";
import { evaluatePolicy } from "../policy/evaluator.js";
import { appendAuditReceipt, createAuditReceipt, readLastReceiptHash } from "../receipt/receipt.js";
import { redactPii, scanPii } from "../scan/pii.js";
import { redactSecrets, scanSecrets } from "../scan/secrets.js";
import type { AuditReceipt, CapabilityGraph, PolicyDecision, PolicyDecisionName, PolicyDocument, RuntimeMode, ScanFinding, TaintLabel } from "../types.js";
import { isToolCallRequest, makeJsonRpcError, parseJsonRpcLine, stringifyJsonRpc, type JsonRpcId } from "./jsonRpc.js";
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
  taintTracker?: TaintTracker;
  runtimeMode?: RuntimeMode;
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

  const runtimeMode = options.runtimeMode ?? "enforce";
  const sessionId = options.sessionId ?? "default";

  try {
    const params = getToolCallParams(message);
    const node = options.graph?.nodes.find((candidate) => candidate.tool === params.name && (!options.server || candidate.server === options.server || !candidate.server));
    let decision = evaluatePolicy(options.policy, {
      tool: params.name,
      server: options.server ?? node?.server,
      arguments: params.arguments,
      capabilityNode: node,
      session_id: sessionId,
      agent: options.agent
    });

    const attackFindings: ScanFinding[] = [];
    const taintLabels = new Set<TaintLabel>();
    let taintSourceLabels: TaintLabel[] = [];

    if (node && options.attackChainDetector && (decision.decision !== "block" || runtimeMode !== "enforce")) {
      const attackDecision = options.attackChainDetector.evaluateCall({
        session_id: sessionId,
        tool: params.name,
        server: options.server ?? node.server,
        capabilities: node.capabilities,
        data_sensitivity: node.data_sensitivity,
        arguments: params.arguments
      });
      if (attackDecision.finding) {
        attackFindings.push(attackDecision.finding);
      }
      if (attackDecision.decision === "block") {
        decision = escalateDecision(decision, "block", attackDecision.reason, "attack_chain_block");
      } else if (attackDecision.decision === "warn" && decision.decision === "allow") {
        decision = escalateDecision(decision, "warn", attackDecision.reason, "attack_chain_review");
      }
    }

    if (node && options.taintTracker) {
      const taintDecision = options.taintTracker.evaluateCall({
        session_id: sessionId,
        tool: params.name,
        server: options.server ?? node.server,
        capabilities: node.capabilities,
        data_sensitivity: node.data_sensitivity,
        arguments: params.arguments
      });
      taintSourceLabels = taintDecision.source_taint_labels;
      for (const label of taintDecision.taint_labels) {
        taintLabels.add(label);
      }
      attackFindings.push(...taintDecision.findings);
      if (taintDecision.decision === "block") {
        decision = escalateDecision(decision, "block", taintDecision.reason, "taint_chain_block");
      }
    }

    if (runtimeMode === "enforce" && decision.decision === "require_approval") {
      const approved = options.interactive && options.approve ? await options.approve(decision) : false;
      if (!approved) {
        decision = {
          ...decision,
          decision: "block",
          reason: `Approval required but not granted: ${decision.reason}`
        };
      }
    }

    const wouldHaveDecision = decision.decision;
    decision = applyRuntimeMode(decision, runtimeMode);
    for (const label of decision.taint_labels ?? []) {
      taintLabels.add(label);
    }

    const finalTaintLabels = [...taintLabels].sort();
    const finalAttackFindings = dedupeFindings([...(decision.attack_chain_findings ?? []), ...attackFindings]);
    const would_have_decision = runtimeMode === "shadow" && wouldHaveDecision !== decision.decision ? wouldHaveDecision : undefined;

    decision = {
      ...decision,
      runtime_mode: runtimeMode,
      would_have_decision,
      taint_labels: finalTaintLabels,
      attack_chain_findings: finalAttackFindings
    };

    const receipt = createAuditReceipt({
      agent: options.agent,
      server: options.server ?? node?.server,
      tool: params.name,
      decision: decision.decision,
      matched_rules: decision.matched_rules,
      arguments: params.arguments,
      policy_hash: options.policy.policy_hash,
      session_id: sessionId,
      previous_receipt_hash: options.auditLogPath ? readLastReceiptHash(options.auditLogPath) : undefined,
      runtime_mode: runtimeMode,
      would_have_decision,
      taint_labels: finalTaintLabels,
      attack_chain_findings: finalAttackFindings
    });

    if (node && options.taintTracker && decision.decision !== "block" && taintSourceLabels.length > 0) {
      options.taintTracker.recordCallSource({
        session_id: sessionId,
        tool: params.name,
        server: options.server ?? node.server,
        capabilities: node.capabilities,
        data_sensitivity: node.data_sensitivity,
        arguments: params.arguments,
        receipt_hash: receipt.receipt_hash
      });
    }

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
  const taintTracker = options.taintTracker ?? new TaintTracker();
  const pendingCalls = new Map<string, { tool: string; server?: string; receipt_hash?: string }>();
  const child = spawn(options.command, options.args, {
    stdio: ["pipe", "pipe", "pipe"],
    shell: process.platform === "win32"
  });

  const upstreamOut = createInterface({ input: child.stdout });
  upstreamOut.on("line", (line) => {
    recordResponseTaint(line, pendingCalls, taintTracker, options.sessionId ?? "default");
    process.stdout.write(`${options.redactResponses === false ? line : redactResponseLine(line)}\n`);
  });

  child.stderr.on("data", (chunk) => {
    process.stderr.write(chunk);
  });

  const clientIn = createInterface({ input: process.stdin });
  clientIn.on("line", (line) => {
    void handleJsonRpcLine(line, {
      ...options,
      taintTracker,
      approve: async (decision) => promptApproval(decision.reason)
    }).then((result) => {
      if (result.action === "forward") {
        rememberPendingToolCall(result.line, result.receipt, pendingCalls);
        child.stdin.write(`${result.line}\n`);
        if (result.decision?.decision === "warn") {
          process.stderr.write(`[capagate] WARN ${result.decision.reason}\n`);
        }
        if (result.decision?.would_have_decision) {
          process.stderr.write(`[capagate] ${result.decision.runtime_mode} would have ${result.decision.would_have_decision}: ${result.decision.reason}\n`);
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

function escalateDecision(decision: PolicyDecision, target: PolicyDecisionName, reason: string, control: string): PolicyDecision {
  if (decision.decision === "block") {
    return {
      ...decision,
      reason,
      required_controls: [...new Set([...decision.required_controls, control])].sort()
    };
  }
  if (target === "warn" && decision.decision !== "allow") {
    return decision;
  }
  return {
    ...decision,
    decision: target,
    reason,
    required_controls: [...new Set([...decision.required_controls, control])].sort()
  };
}

function applyRuntimeMode(decision: PolicyDecision, runtimeMode: RuntimeMode): PolicyDecision {
  if (runtimeMode === "enforce") {
    return {
      ...decision,
      runtime_mode: runtimeMode
    };
  }

  if (runtimeMode === "shadow") {
    if (decision.decision === "block" || decision.decision === "require_approval") {
      return {
        ...decision,
        decision: "allow",
        reason: `Shadow mode forwarded call; would have ${decision.decision}: ${decision.reason}`,
        runtime_mode: runtimeMode,
        required_controls: [...new Set([...decision.required_controls, "shadow_mode_review"])].sort()
      };
    }
    return {
      ...decision,
      runtime_mode: runtimeMode
    };
  }

  return {
    ...decision,
    decision: "allow",
    reason: `Audit-only mode forwarded call; observed policy decision was ${decision.decision}: ${decision.reason}`,
    runtime_mode: runtimeMode,
    required_controls: [...new Set([...decision.required_controls, "audit_only_review"])].sort()
  };
}

function rememberPendingToolCall(line: string, receipt: AuditReceipt | undefined, pendingCalls: Map<string, { tool: string; server?: string; receipt_hash?: string }>): void {
  try {
    const message = parseJsonRpcLine(line);
    if (!isToolCallRequest(message) || message.id === undefined) {
      return;
    }
    const params = getToolCallParams(message);
    pendingCalls.set(idKey(message.id), { tool: params.name, receipt_hash: receipt?.receipt_hash });
  } catch {
    return;
  }
}

function recordResponseTaint(line: string, pendingCalls: Map<string, { tool: string; server?: string; receipt_hash?: string }>, taintTracker: TaintTracker, sessionId: string): void {
  try {
    const message = parseJsonRpcLine(line) as Record<string, unknown>;
    if (!Object.prototype.hasOwnProperty.call(message, "id")) {
      return;
    }
    const pending = pendingCalls.get(idKey(message.id as JsonRpcId));
    if (!pending) {
      return;
    }
    taintTracker.recordResponseLine({
      session_id: sessionId,
      tool: pending.tool,
      server: pending.server,
      line,
      receipt_hash: pending.receipt_hash
    });
    pendingCalls.delete(idKey(message.id as JsonRpcId));
  } catch {
    return;
  }
}

function idKey(id: JsonRpcId): string {
  return String(id ?? "null");
}

function dedupeFindings(findings: ScanFinding[]): ScanFinding[] {
  const seen = new Set<string>();
  const out: ScanFinding[] = [];
  for (const finding of findings) {
    const key = `${finding.id}:${finding.message}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(finding);
    }
  }
  return out;
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
