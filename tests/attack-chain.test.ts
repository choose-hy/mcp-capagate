import { describe, expect, it } from "vitest";
import { AttackChainDetector } from "../packages/core/src/index.js";

describe("attack-chain detector", () => {
  it("blocks external send after private read", () => {
    const detector = new AttackChainDetector();
    detector.evaluateCall({
      session_id: "s1",
      tool: "read_customer_profile",
      capabilities: ["read_data", "private_data_access"],
      data_sensitivity: "private"
    });
    const decision = detector.evaluateCall({
      session_id: "s1",
      tool: "send_email",
      capabilities: ["send_message", "external_network"],
      data_sensitivity: "public"
    });
    expect(decision.decision).toBe("block");
    expect(decision.reason).toContain("read sensitive data");
  });
});
