import type { Capability, CapabilityNode, DataSensitivity, RiskLevel } from "../types.js";

const riskRank: Record<RiskLevel, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export function maxRisk(...risks: RiskLevel[]): RiskLevel {
  return risks.sort((a, b) => riskRank[b] - riskRank[a])[0] ?? "low";
}

export function scoreRisk(capabilities: Capability[]): {
  risk_level: RiskLevel;
  data_sensitivity: DataSensitivity;
  blast_radius: RiskLevel;
  required_controls: string[];
} {
  const set = new Set(capabilities);
  let risk: RiskLevel = "low";
  const controls = new Set<string>();

  if (set.has("shell_execution") || set.has("execute_code")) {
    risk = "critical";
    controls.add("block_by_default");
    controls.add("explicit_operator_approval");
  }

  if (set.has("credential_access") && (set.has("external_network") || set.has("send_message") || set.has("webhook_post"))) {
    risk = "critical";
    controls.add("secret_redaction");
    controls.add("destination_allowlist");
  }

  if (set.has("delete_data") || set.has("financial_action")) {
    risk = maxRisk(risk, "critical");
    controls.add("business_confirmation");
    controls.add("idempotency_key");
  }

  if (set.has("filesystem_write") || set.has("database_write") || set.has("send_message")) {
    risk = maxRisk(risk, "high");
    controls.add("human_approval");
  }

  if (set.has("filesystem_read") && set.has("private_data_access")) {
    risk = maxRisk(risk, "high");
    controls.add("path_allowlist");
    controls.add("response_redaction");
  }

  if (set.has("private_data_access") || set.has("cross_system_exfiltration") || set.has("admin_action")) {
    risk = maxRisk(risk, "high");
    controls.add("least_privilege_identity");
  }

  if (set.has("database_query")) {
    risk = maxRisk(risk, set.has("private_data_access") ? "high" : "medium");
    controls.add("query_scope_limit");
  }

  if (set.has("write_data") || set.has("external_network") || set.has("webhook_post") || set.has("unknown")) {
    risk = maxRisk(risk, "medium");
  }

  if (set.has("unknown")) {
    controls.add("fail_closed_review");
  }

  const data_sensitivity = deriveSensitivity(set);
  const blast_radius = deriveBlastRadius(set, risk);
  return {
    risk_level: risk,
    data_sensitivity,
    blast_radius,
    required_controls: [...controls].sort()
  };
}

export function scoreCapabilityNode(node: Omit<CapabilityNode, "risk_level" | "data_sensitivity" | "blast_radius" | "required_controls">): CapabilityNode {
  return {
    ...node,
    ...scoreRisk(node.capabilities)
  };
}

function deriveSensitivity(capabilities: Set<Capability>): DataSensitivity {
  if (capabilities.has("credential_access")) {
    return "secret";
  }
  if (capabilities.has("private_data_access") || capabilities.has("identity_access")) {
    return "private";
  }
  if (capabilities.has("write_data") || capabilities.has("database_query") || capabilities.has("filesystem_read")) {
    return "internal";
  }
  return "public";
}

function deriveBlastRadius(capabilities: Set<Capability>, risk: RiskLevel): RiskLevel {
  if (risk === "critical") {
    return "critical";
  }
  if (capabilities.has("external_network") || capabilities.has("send_message") || capabilities.has("database_write") || capabilities.has("filesystem_write")) {
    return "high";
  }
  if (capabilities.has("private_data_access") || capabilities.has("database_query") || capabilities.has("write_data")) {
    return "medium";
  }
  return "low";
}
