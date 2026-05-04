import { describe, expect, it } from "vitest";
import { createAuditReceipt } from "../packages/core/src/index.js";

describe("audit receipts", () => {
  it("creates stable hashes for identical inputs", () => {
    const input = {
      timestamp: "2026-01-01T00:00:00.000Z",
      tool: "read_order",
      decision: "allow" as const,
      matched_rules: ["tool.local.read_order"],
      arguments: { order_id: "ord_1" },
      policy_hash: "policy",
      session_id: "session"
    };
    const one = createAuditReceipt(input);
    const two = createAuditReceipt(input);
    expect(one.receipt_hash).toBe(two.receipt_hash);
    expect(one.arguments_hash).toBe(two.arguments_hash);
  });
});
