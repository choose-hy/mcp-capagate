import type { ScanFinding } from "../types.js";
import { sha256 } from "../schema.js";

const PII_PATTERNS: Array<{ name: string; regex: RegExp; replacement: string; severity: "medium" | "high" }> = [
  { name: "email", regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, replacement: "[REDACTED_EMAIL]", severity: "medium" },
  { name: "phone", regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: "[REDACTED_PHONE]", severity: "medium" },
  { name: "credit_card_like", regex: /\b(?:\d[ -]*?){13,19}\b/g, replacement: "[REDACTED_CARD]", severity: "high" },
  { name: "ssn_like", regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: "[REDACTED_SSN]", severity: "high" }
];

export function scanPii(text: string, path = "response"): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const pattern of PII_PATTERNS) {
    if (pattern.regex.test(text)) {
      findings.push({
        id: sha256(`pii:${path}:${pattern.name}:${text.length}`).slice(0, 16),
        type: "pii",
        severity: pattern.severity,
        path,
        message: `PII-like value detected by ${pattern.name}.`,
        recommendation: "Redact or minimize private data before returning it to the agent."
      });
      pattern.regex.lastIndex = 0;
    }
  }
  return findings;
}

export function redactPii(text: string): string {
  return PII_PATTERNS.reduce((current, pattern) => current.replace(pattern.regex, pattern.replacement), text);
}

export function redactSensitiveText(text: string): string {
  return redactPii(text);
}
