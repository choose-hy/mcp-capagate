export type RiskLevel = "low" | "medium" | "high" | "critical";
export type DataSensitivity = "public" | "internal" | "private" | "secret";
export type PolicyDecisionName = "allow" | "warn" | "require_approval" | "block";
export type RuntimeMode = "enforce" | "shadow" | "audit-only";
export type TaintLabel = "secret_read" | "private_data_read" | "credential_access" | "filesystem_sensitive_read" | "customer_data_read";
export type ConstraintStatus = "pass" | "fail";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type Capability =
  | "read_data"
  | "write_data"
  | "delete_data"
  | "execute_code"
  | "send_message"
  | "external_network"
  | "financial_action"
  | "identity_access"
  | "credential_access"
  | "database_query"
  | "database_write"
  | "filesystem_read"
  | "filesystem_write"
  | "shell_execution"
  | "browser_automation"
  | "admin_action"
  | "private_data_access"
  | "cross_system_exfiltration"
  | "webhook_post"
  | "unknown";

export interface MCPToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  server?: string;
}

export interface CapabilityEvidence {
  capability: Capability;
  source: string;
  match: string;
  confidence: number;
}

export interface CapabilityNode {
  id: string;
  tool: string;
  server?: string;
  capabilities: Capability[];
  risk_level: RiskLevel;
  data_sensitivity: DataSensitivity;
  blast_radius: RiskLevel;
  preconditions: string[];
  effects: string[];
  required_controls: string[];
  evidence: CapabilityEvidence[];
  confidence: number;
}

export type CapabilityEdgeKind =
  | "can_exfiltrate_to"
  | "can_read_then_send"
  | "can_mutate_state"
  | "can_execute_code"
  | "can_access_private_data"
  | "potential_shadowing"
  | "potential_tool_chain";

export interface CapabilityEdge {
  id: string;
  from: string;
  to: string;
  type: CapabilityEdgeKind;
  reason: string;
  risk_level: RiskLevel;
}

export interface GraphSummary {
  tool_count: number;
  node_count: number;
  edge_count: number;
  risk_counts: Record<RiskLevel, number>;
  capability_counts: Partial<Record<Capability, number>>;
  finding_counts?: Partial<Record<FindingSeverity, number>>;
}

export interface ScanFinding {
  id: string;
  type:
    | "tool_poisoning"
    | "hidden_unicode"
    | "schema_injection"
    | "pii"
    | "secret"
    | "ambiguous_tool_name"
    | "external_network_sink"
    | "cross_server_shadowing"
    | "risky_capability"
    | "attack_chain";
  severity: FindingSeverity;
  tool?: string;
  server?: string;
  path?: string;
  message: string;
  evidence?: string;
  recommendation?: string;
}

export interface CapabilityGraph {
  generated_at: string;
  source: string;
  tools: MCPToolDefinition[];
  nodes: CapabilityNode[];
  edges: CapabilityEdge[];
  summary: GraphSummary;
  findings?: ScanFinding[];
  graph_hash: string;
}

export interface BlockedArgumentPattern {
  path: string;
  pattern: string;
  reason: string;
}

export interface PolicyConstraints {
  path_prefixes?: string[];
  allowed_domains?: string[];
  blocked_domains?: string[];
  max_amount?: number;
  required_boolean_flags?: string[];
  blocked_argument_patterns?: BlockedArgumentPattern[];
  required_argument_paths?: string[];
  blocked_argument_paths?: string[];
}

export interface ConstraintFinding {
  status: ConstraintStatus;
  reason: string;
  matched_constraint: keyof PolicyConstraints | "none";
  argument_path?: string;
  value_preview?: string;
}

export interface ConstraintEvaluation {
  status: ConstraintStatus;
  findings: ConstraintFinding[];
}

export interface PolicyRule {
  id: string;
  match: {
    tool?: string;
    server?: string;
    capabilities?: Capability[];
    risk_level?: RiskLevel | RiskLevel[];
    data_sensitivity?: DataSensitivity | DataSensitivity[];
  };
  decision: PolicyDecisionName;
  reason: string;
  constraints?: PolicyConstraints;
  controls: string[];
  priority: number;
}

export interface PolicyDocument {
  version: "0.1";
  generated_at: string;
  defaults: {
    unknown_tool: PolicyDecisionName;
    fail_closed: boolean;
    redact_response: boolean;
  };
  rules: PolicyRule[];
  policy_hash: string;
}

export interface RuntimeTaintSource {
  label: TaintLabel;
  source_tool: string;
  source_argument_paths: string[];
  timestamp: string;
  receipt_hash?: string;
}

export interface PolicyDecision {
  decision: PolicyDecisionName;
  reason: string;
  matched_rules: string[];
  required_controls: string[];
  redact_response: boolean;
  receipt?: AuditReceipt;
  constraint_findings?: ConstraintFinding[];
  runtime_mode?: RuntimeMode;
  would_have_decision?: PolicyDecisionName;
  taint_labels?: TaintLabel[];
  attack_chain_findings?: ScanFinding[];
}

export interface ToolCallContext {
  tool: string;
  server?: string;
  arguments?: unknown;
  capabilityNode?: CapabilityNode;
  session_id?: string;
  agent?: string;
}

export interface AuditReceipt {
  id: string;
  timestamp: string;
  agent?: string;
  server?: string;
  tool: string;
  decision: PolicyDecisionName;
  matched_rules: string[];
  arguments_hash: string;
  policy_hash: string;
  session_id: string;
  previous_receipt_hash?: string;
  runtime_mode?: RuntimeMode;
  would_have_decision?: PolicyDecisionName;
  taint_labels?: TaintLabel[];
  attack_chain_findings?: ScanFinding[];
  receipt_hash: string;
}

export interface DriftFinding {
  id: string;
  type:
    | "new_tool"
    | "removed_tool"
    | "description_change"
    | "schema_change"
    | "risk_change"
    | "capability_change"
    | "hash_change";
  severity: FindingSeverity;
  tool: string;
  server?: string;
  message: string;
  before?: unknown;
  after?: unknown;
}

export interface DriftReport {
  generated_at: string;
  baseline_hash: string;
  current_hash: string;
  findings: DriftFinding[];
  should_fail: boolean;
}

export interface AttackChainEvent {
  session_id: string;
  tool: string;
  server?: string;
  capabilities: Capability[];
  data_sensitivity: DataSensitivity;
  arguments?: unknown;
}

export interface AttackChainDecision {
  decision: PolicyDecisionName;
  reason: string;
  finding?: ScanFinding;
}
