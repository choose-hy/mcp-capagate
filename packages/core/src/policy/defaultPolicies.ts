import type { PolicyDecisionName } from "../types.js";

export const DEFAULT_POLICY_CONFIG = {
  unknown_tool: "block" as PolicyDecisionName,
  fail_closed: true,
  redact_response: true
};

export const DEFAULT_CONTROL_REASONS: Record<string, string> = {
  block_by_default: "Capability is too dangerous for unattended execution.",
  explicit_operator_approval: "A human should approve code or shell execution.",
  secret_redaction: "Secret-looking output should be redacted before it leaves the proxy.",
  destination_allowlist: "External destinations should be constrained to expected hosts or channels.",
  business_confirmation: "Financial and destructive workflows need a confirmed business event.",
  idempotency_key: "State-changing operations should be replay-safe.",
  human_approval: "High-impact tool calls need approval in non-shadow mode.",
  path_allowlist: "Filesystem access should be scoped to approved paths.",
  response_redaction: "Private output should be scanned and redacted.",
  least_privilege_identity: "The MCP server should run with a least-privilege identity.",
  query_scope_limit: "Database reads should be constrained by tenant and row limits.",
  fail_closed_review: "Unknown tools should be reviewed before they are allowed."
};
