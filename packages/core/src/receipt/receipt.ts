import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { AuditReceipt, PolicyDecisionName, RuntimeMode, ScanFinding, TaintLabel } from "../types.js";
import { sha256 } from "../schema.js";

export interface CreateReceiptInput {
  timestamp?: string;
  agent?: string;
  server?: string;
  tool: string;
  decision: PolicyDecisionName;
  matched_rules: string[];
  arguments?: unknown;
  policy_hash: string;
  session_id: string;
  previous_receipt_hash?: string;
  runtime_mode?: RuntimeMode;
  would_have_decision?: PolicyDecisionName;
  taint_labels?: TaintLabel[];
  attack_chain_findings?: ScanFinding[];
}

export function createAuditReceipt(input: CreateReceiptInput): AuditReceipt {
  const timestamp = input.timestamp ?? new Date().toISOString();
  const arguments_hash = sha256(input.arguments ?? {});
  const unsigned = {
    id: "",
    timestamp,
    agent: input.agent,
    server: input.server,
    tool: input.tool,
    decision: input.decision,
    matched_rules: input.matched_rules,
    arguments_hash,
    policy_hash: input.policy_hash,
    session_id: input.session_id,
    previous_receipt_hash: input.previous_receipt_hash,
    runtime_mode: input.runtime_mode,
    would_have_decision: input.would_have_decision,
    taint_labels: input.taint_labels,
    attack_chain_findings: input.attack_chain_findings
  };
  const id = sha256(unsigned).slice(0, 24);
  const receiptWithoutHash = { ...unsigned, id };
  return {
    ...receiptWithoutHash,
    receipt_hash: sha256(receiptWithoutHash)
  };
}

export function appendAuditReceipt(path: string, receipt: AuditReceipt): void {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify(receipt)}\n`, "utf8");
}

export function readAuditReceipts(path: string): AuditReceipt[] {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as AuditReceipt);
}

export function readLastReceiptHash(path: string): string | undefined {
  const receipts = readAuditReceipts(path);
  return receipts.at(-1)?.receipt_hash;
}