import type { ScanFinding } from "../types.js";
import { sha256 } from "../schema.js";

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; replacement: string }> = [
  { name: "openai_key", regex: /sk-[A-Za-z0-9_-]{20,}/g, replacement: "sk-[REDACTED]" },
  { name: "github_token", regex: /ghp_[A-Za-z0-9_]{20,}/g, replacement: "ghp_[REDACTED]" },
  { name: "aws_access_key", regex: /AKIA[0-9A-Z]{16}/g, replacement: "AKIA[REDACTED]" },
  { name: "api_key_assignment", regex: /\b(api[_-]?key|token|secret|password)=['"]?[^'"\s]+/gi, replacement: "$1=[REDACTED]" },
  { name: "private_key", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: "-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----" }
];

export function scanSecrets(text: string, path = "response"): ScanFinding[] {
  const findings: ScanFinding[] = [];
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.regex.test(text)) {
      findings.push({
        id: sha256(`secret:${path}:${pattern.name}:${text.length}`).slice(0, 16),
        type: "secret",
        severity: "critical",
        path,
        message: `Secret-like value detected by ${pattern.name}.`,
        recommendation: "Redact the response and rotate the exposed credential if it was real."
      });
      pattern.regex.lastIndex = 0;
    }
  }
  return findings;
}

export function redactSecrets(text: string): string {
  return SECRET_PATTERNS.reduce((current, pattern) => current.replace(pattern.regex, pattern.replacement), text);
}
