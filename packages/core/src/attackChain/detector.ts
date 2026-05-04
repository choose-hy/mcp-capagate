import type { AttackChainDecision, AttackChainEvent, Capability, ScanFinding } from "../types.js";
import { sha256 } from "../schema.js";

interface SessionState {
  taintedByPrivateRead?: AttackChainEvent;
  taintedBySecretRead?: AttackChainEvent;
  recentFileWrite?: AttackChainEvent;
  recentExternalNetwork?: AttackChainEvent;
  events: AttackChainEvent[];
}

const EXTERNAL_SINKS: Capability[] = ["send_message", "external_network", "webhook_post", "browser_automation"];

export class AttackChainDetector {
  private readonly sessions = new Map<string, SessionState>();

  evaluateCall(event: AttackChainEvent): AttackChainDecision {
    const state = this.getSession(event.session_id);
    const caps = new Set(event.capabilities);

    if ((state.taintedBySecretRead || state.taintedByPrivateRead) && EXTERNAL_SINKS.some((capability) => caps.has(capability))) {
      const source = state.taintedBySecretRead ?? state.taintedByPrivateRead;
      const finding = this.finding("attack_chain", event, `Blocked ${event.tool} because ${source?.tool ?? "a previous tool"} read sensitive data in the same session.`);
      this.record(state, event);
      return {
        decision: "block",
        reason: finding.message,
        finding
      };
    }

    if (state.recentFileWrite && (caps.has("shell_execution") || caps.has("execute_code"))) {
      const finding = this.finding("tool_poisoning", event, `Blocked ${event.tool} after ${state.recentFileWrite.tool}; file write followed by execution is a persistence risk.`);
      this.record(state, event);
      return {
        decision: "block",
        reason: finding.message,
        finding
      };
    }

    if (state.recentExternalNetwork && (caps.has("private_data_access") || caps.has("credential_access"))) {
      const finding = this.finding("attack_chain", event, `Sensitive read after external-network activity should be reviewed in session ${event.session_id}.`);
      this.record(state, event);
      return {
        decision: "warn",
        reason: finding.message,
        finding
      };
    }

    this.record(state, event);
    return {
      decision: "allow",
      reason: "No session-level attack chain detected."
    };
  }

  reset(sessionId?: string): void {
    if (sessionId) {
      this.sessions.delete(sessionId);
      return;
    }
    this.sessions.clear();
  }

  private getSession(sessionId: string): SessionState {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      return existing;
    }
    const state: SessionState = { events: [] };
    this.sessions.set(sessionId, state);
    return state;
  }

  private record(state: SessionState, event: AttackChainEvent): void {
    const caps = new Set(event.capabilities);
    if (event.data_sensitivity === "secret" || caps.has("credential_access")) {
      state.taintedBySecretRead = event;
    }
    if (event.data_sensitivity === "private" || caps.has("private_data_access")) {
      state.taintedByPrivateRead = event;
    }
    if (caps.has("filesystem_write") || caps.has("write_data")) {
      state.recentFileWrite = event;
    }
    if (caps.has("external_network") || caps.has("webhook_post")) {
      state.recentExternalNetwork = event;
    }
    state.events.push(event);
    if (state.events.length > 20) {
      state.events.shift();
    }
  }

  private finding(type: ScanFinding["type"], event: AttackChainEvent, message: string): ScanFinding {
    return {
      id: sha256(`attack_chain:${event.session_id}:${event.tool}:${message}`).slice(0, 16),
      type,
      severity: "critical",
      tool: event.tool,
      server: event.server,
      message,
      recommendation: "Split the session, require approval, or block external sinks after sensitive reads."
    };
  }
}
