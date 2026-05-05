import type { AttackChainDecision, AttackChainEvent, Capability, RuntimeTaintSource, ScanFinding, TaintLabel } from "../types.js";
import { sha256 } from "../schema.js";
import { scanPii } from "../scan/pii.js";
import { scanSecrets } from "../scan/secrets.js";

export interface TaintCallEvaluation {
  decision: AttackChainDecision["decision"];
  reason: string;
  taint_labels: TaintLabel[];
  source_taint_labels: TaintLabel[];
  active_taint_labels: TaintLabel[];
  findings: ScanFinding[];
}

export interface RecordTaintInput extends AttackChainEvent {
  receipt_hash?: string;
}

interface ArgumentEntry {
  path: string;
  key: string;
  value: unknown;
}

interface SessionTaintState {
  sources: RuntimeTaintSource[];
}

const EXTERNAL_SINKS: Capability[] = ["send_message", "external_network", "webhook_post", "browser_automation"];
const PATH_KEYS = new Set(["path", "file", "file_path", "source_path", "destination_path", "working_directory"]);
const SECRET_ARGUMENT_PATTERN = /(^|[:\\/.])\.env($|[\\/])|id_rsa|private[_-]?key|secrets?|credentials?|token/i;
const PRIVATE_ARGUMENT_PATTERN = /customer|ssn|pii/i;

export class TaintTracker {
  private readonly sessions = new Map<string, SessionTaintState>();

  evaluateCall(event: AttackChainEvent): TaintCallEvaluation {
    const state = this.getSession(event.session_id);
    const activeLabels = uniqueLabels(state.sources.map((source) => source.label));
    const sourceLabels = this.labelsForEvent(event);
    const sink = this.isSink(event);
    const findings: ScanFinding[] = [];

    if (activeLabels.length > 0 && sink) {
      findings.push(this.sinkFinding(event, state.sources, sink));
    }

    return {
      decision: findings.length > 0 ? "block" : "allow",
      reason: findings[0]?.message ?? "No tainted source reaches this tool call.",
      taint_labels: uniqueLabels([...activeLabels, ...sourceLabels]),
      source_taint_labels: sourceLabels,
      active_taint_labels: activeLabels,
      findings
    };
  }

  recordCallSource(input: RecordTaintInput): RuntimeTaintSource[] {
    const labels = this.labelsForEvent(input);
    if (labels.length === 0) {
      return [];
    }

    const paths = sensitiveArgumentPaths(input.arguments);
    const state = this.getSession(input.session_id);
    const timestamp = new Date().toISOString();
    const sources = labels.map((label): RuntimeTaintSource => ({
      label,
      source_tool: input.tool,
      source_argument_paths: paths,
      timestamp,
      receipt_hash: input.receipt_hash
    }));
    state.sources.push(...sources);
    if (state.sources.length > 50) {
      state.sources.splice(0, state.sources.length - 50);
    }
    return sources;
  }

  recordResponseLine(input: { session_id: string; tool: string; server?: string; line: string; receipt_hash?: string }): RuntimeTaintSource[] {
    const secretFindings = scanSecrets(input.line);
    const piiFindings = scanPii(input.line);
    const labels: TaintLabel[] = [];
    if (secretFindings.length > 0) {
      labels.push("secret_read");
    }
    if (piiFindings.length > 0) {
      labels.push("private_data_read");
    }
    if (labels.length === 0) {
      return [];
    }

    const state = this.getSession(input.session_id);
    const timestamp = new Date().toISOString();
    const sources = uniqueLabels(labels).map((label): RuntimeTaintSource => ({
      label,
      source_tool: input.tool,
      source_argument_paths: ["response"],
      timestamp,
      receipt_hash: input.receipt_hash
    }));
    state.sources.push(...sources);
    return sources;
  }

  getTaintLabels(sessionId: string): TaintLabel[] {
    return uniqueLabels(this.getSession(sessionId).sources.map((source) => source.label));
  }

  getSources(sessionId: string): RuntimeTaintSource[] {
    return [...this.getSession(sessionId).sources];
  }

  reset(sessionId?: string): void {
    if (sessionId) {
      this.sessions.delete(sessionId);
      return;
    }
    this.sessions.clear();
  }

  private getSession(sessionId: string): SessionTaintState {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      return existing;
    }
    const state: SessionTaintState = { sources: [] };
    this.sessions.set(sessionId, state);
    return state;
  }

  private labelsForEvent(event: AttackChainEvent): TaintLabel[] {
    const labels: TaintLabel[] = [];
    const caps = new Set(event.capabilities);
    const readLike = caps.has("read_data") || caps.has("filesystem_read") || caps.has("database_query") || caps.has("private_data_access") || caps.has("credential_access");

    if (caps.has("credential_access") || event.data_sensitivity === "secret") {
      labels.push("credential_access", "secret_read");
    }

    if (caps.has("private_data_access") || event.data_sensitivity === "private") {
      labels.push("private_data_read");
    }

    if (readLike) {
      for (const entry of collectArgumentEntries(event.arguments)) {
        const value = typeof entry.value === "string" ? entry.value : "";
        const haystack = `${entry.path}:${value}`;
        if (SECRET_ARGUMENT_PATTERN.test(haystack)) {
          labels.push("secret_read");
          if (isPathLike(entry)) {
            labels.push("filesystem_sensitive_read");
          }
        }
        if (PRIVATE_ARGUMENT_PATTERN.test(haystack)) {
          labels.push("private_data_read");
          if (/customer/i.test(haystack)) {
            labels.push("customer_data_read");
          }
        }
      }
    }

    if (/customer/i.test(event.tool) && (caps.has("read_data") || caps.has("private_data_access"))) {
      labels.push("customer_data_read");
    }

    return uniqueLabels(labels);
  }

  private isSink(event: AttackChainEvent): string | undefined {
    const caps = new Set(event.capabilities);
    if (EXTERNAL_SINKS.some((capability) => caps.has(capability))) {
      return "external sink";
    }

    if ((caps.has("filesystem_write") || caps.has("write_data")) && writesOutsideWorkspace(event.arguments)) {
      return "filesystem write outside workspace";
    }

    return undefined;
  }

  private sinkFinding(event: AttackChainEvent, sources: RuntimeTaintSource[], sink: string): ScanFinding {
    const labels = uniqueLabels(sources.map((source) => source.label));
    const sourceTools = [...new Set(sources.map((source) => source.source_tool))].slice(0, 3).join(", ");
    const message = `Blocked ${event.tool} because ${sink} follows tainted session data (${labels.join(", ")}) from ${sourceTools}.`;
    return {
      id: sha256(`taint:${event.session_id}:${event.tool}:${message}`).slice(0, 16),
      type: "attack_chain",
      severity: "critical",
      tool: event.tool,
      server: event.server,
      message,
      evidence: labels.join(", "),
      recommendation: "Use a new session, require explicit approval, or keep sensitive reads away from external sinks."
    };
  }
}

function collectArgumentEntries(value: unknown, prefix = ""): ArgumentEntry[] {
  if (value === null || value === undefined) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectArgumentEntries(item, `${prefix}[${index}]`));
  }
  if (typeof value === "object") {
    const entries: ArgumentEntry[] = [];
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${key}` : key;
      entries.push({ path, key, value: child });
      entries.push(...collectArgumentEntries(child, path));
    }
    return entries;
  }
  return prefix ? [{ path: prefix, key: prefix.split(/[.\[\]]/).filter(Boolean).at(-1) ?? prefix, value }] : [];
}

function sensitiveArgumentPaths(value: unknown): string[] {
  return collectArgumentEntries(value)
    .filter((entry) => {
      const rendered = typeof entry.value === "string" ? entry.value : "";
      return SECRET_ARGUMENT_PATTERN.test(`${entry.path}:${rendered}`) || PRIVATE_ARGUMENT_PATTERN.test(`${entry.path}:${rendered}`);
    })
    .map((entry) => entry.path);
}

function isPathLike(entry: ArgumentEntry): boolean {
  return PATH_KEYS.has(entry.key.toLowerCase()) || /path|file|directory/i.test(entry.key);
}

function writesOutsideWorkspace(args: unknown): boolean {
  const paths = collectArgumentEntries(args).filter((entry) => isPathLike(entry) && typeof entry.value === "string");
  return paths.some((entry) => {
    const value = String(entry.value).replace(/\\/g, "/").trim();
    return value.startsWith("/") || /^[a-z]:\//i.test(value) || value.split("/").includes("..");
  });
}

function uniqueLabels(labels: TaintLabel[]): TaintLabel[] {
  return [...new Set(labels)].sort();
}
