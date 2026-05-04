import type { Capability } from "../types.js";

export const CAPABILITIES: Capability[] = [
  "read_data",
  "write_data",
  "delete_data",
  "execute_code",
  "send_message",
  "external_network",
  "financial_action",
  "identity_access",
  "credential_access",
  "database_query",
  "database_write",
  "filesystem_read",
  "filesystem_write",
  "shell_execution",
  "browser_automation",
  "admin_action",
  "private_data_access",
  "cross_system_exfiltration",
  "webhook_post",
  "unknown"
];

export interface CapabilityRule {
  capability: Capability;
  regex: RegExp;
  confidence: number;
  effect: string;
}

export const CAPABILITY_RULES: CapabilityRule[] = [
  { capability: "read_data", regex: /\b(read|get|list|search|lookup|retrieve|fetch|view|show)\b/i, confidence: 0.78, effect: "Reads data from a tool or backend." },
  { capability: "write_data", regex: /\b(write|update|create|modify|patch|save|set|add|append|put)\b/i, confidence: 0.8, effect: "Writes or changes stored state." },
  { capability: "delete_data", regex: /\b(delete|remove|destroy|drop|purge|erase|cancel)\b/i, confidence: 0.88, effect: "Deletes, cancels, or destroys state." },
  { capability: "execute_code", regex: /\b(exec|execute|run_code|eval|script|spawn|subprocess|python|node)\b/i, confidence: 0.9, effect: "Executes code or commands." },
  { capability: "shell_execution", regex: /\b(shell|terminal|command|cmd|powershell|bash|sh|execute_shell)\b/i, confidence: 0.93, effect: "Executes operating-system shell commands." },
  { capability: "send_message", regex: /\b(email|send|message|slack|notify|sms|reply|forward)\b/i, confidence: 0.86, effect: "Sends a message to a person or external channel." },
  { capability: "external_network", regex: /\b(http|https|url|fetch|request|webhook|post|external|internet|api|endpoint|email|slack)\b/i, confidence: 0.82, effect: "Reaches an external network or communication sink." },
  { capability: "financial_action", regex: /\b(refund|payment|charge|transfer|invoice|payout|billing|credit|debit)\b/i, confidence: 0.9, effect: "Initiates or modifies a financial workflow." },
  { capability: "identity_access", regex: /\b(identity|user|profile|account|iam|role|permission|login|auth)\b/i, confidence: 0.74, effect: "Accesses identity or account metadata." },
  { capability: "credential_access", regex: /\b(token|secret|credential|password|api[_ -]?key|private[_ -]?key|authorization|bearer|env)\b/i, confidence: 0.92, effect: "Touches credentials, keys, or secret material." },
  { capability: "database_query", regex: /\b(sql|query|database|db|select|table|collection)\b/i, confidence: 0.78, effect: "Queries database-like storage." },
  { capability: "database_write", regex: /\b(insert|upsert|migration|truncate|database[_ -]?write|db[_ -]?write)\b/i, confidence: 0.86, effect: "Writes database-like storage." },
  { capability: "filesystem_read", regex: /\b(read_file|file|path|directory|folder|download|open_file)\b/i, confidence: 0.75, effect: "Reads local filesystem data." },
  { capability: "filesystem_write", regex: /\b(write_file|save_file|upload|overwrite|mkdir|rename|file_path|destination_path)\b/i, confidence: 0.8, effect: "Writes local filesystem data." },
  { capability: "browser_automation", regex: /\b(browser|click|navigate|screenshot|dom|playwright|selenium)\b/i, confidence: 0.84, effect: "Controls a browser or page session." },
  { capability: "admin_action", regex: /\b(admin|root|sudo|privilege|policy|permission|delete_user|ban_user)\b/i, confidence: 0.82, effect: "Performs privileged administrative action." },
  { capability: "private_data_access", regex: /\b(ssn|phone|email|address|customer|profile|patient|employee|private|personal|pii)\b/i, confidence: 0.84, effect: "Touches private or personal data." },
  { capability: "webhook_post", regex: /\b(webhook|callback_url|post_url|notify_url)\b/i, confidence: 0.88, effect: "Posts data to a webhook-like sink." }
];

export const READ_ONLY_CAPABILITIES: Capability[] = ["read_data", "filesystem_read", "database_query"];
export const WRITE_CAPABILITIES: Capability[] = ["write_data", "filesystem_write", "database_write", "delete_data", "financial_action", "admin_action"];
export const EXFILTRATION_SINK_CAPABILITIES: Capability[] = ["send_message", "external_network", "webhook_post", "browser_automation"];
