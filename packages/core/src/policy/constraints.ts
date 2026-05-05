import type { ConstraintEvaluation, ConstraintFinding, PolicyConstraints } from "../types.js";

interface ArgumentEntry {
  path: string;
  key: string;
  value: unknown;
}

const PATH_KEYS = new Set(["path", "file", "file_path", "filepath", "source_path", "sourcepath", "destination_path", "destinationpath"]);
const AMOUNT_KEYS = new Set(["amount", "refund_amount", "refundamount", "payment_amount", "paymentamount", "total", "amount_cents", "amountcents", "total_cents", "totalcents"]);
const DOMAIN_KEYS = new Set(["email", "recipient", "to", "url", "webhook", "webhook_url", "webhookurl", "endpoint", "endpoint_url", "endpointurl", "callback_url", "callbackurl", "post_url", "posturl", "notify_url", "notifyurl"]);

export function evaluateConstraints(constraints: PolicyConstraints | undefined, args: unknown): ConstraintEvaluation {
  if (!constraints || Object.keys(constraints).length === 0) {
    return { status: "pass", findings: [] };
  }

  const entries = collectArgumentEntries(args);
  const findings: ConstraintFinding[] = [];

  findings.push(...evaluateRequiredArgumentPaths(constraints, entries));
  findings.push(...evaluateBlockedArgumentPaths(constraints, entries));
  findings.push(...evaluateRequiredBooleanFlags(constraints, entries));
  findings.push(...evaluatePathPrefixes(constraints, entries));
  findings.push(...evaluateDomainConstraints(constraints, entries));
  findings.push(...evaluateMaxAmount(constraints, entries));
  findings.push(...evaluateBlockedPatterns(constraints, entries));

  return {
    status: findings.length > 0 ? "fail" : "pass",
    findings
  };
}

function evaluateRequiredArgumentPaths(constraints: PolicyConstraints, entries: ArgumentEntry[]): ConstraintFinding[] {
  return (constraints.required_argument_paths ?? [])
    .filter((path) => !hasArgumentPath(entries, path))
    .map((path) => ({
      status: "fail" as const,
      reason: `Required argument path ${path} is missing.`,
      matched_constraint: "required_argument_paths" as const,
      argument_path: path
    }));
}

function evaluateBlockedArgumentPaths(constraints: PolicyConstraints, entries: ArgumentEntry[]): ConstraintFinding[] {
  return (constraints.blocked_argument_paths ?? [])
    .flatMap((path) => entriesForPath(entries, path))
    .map((entry) => ({
      status: "fail" as const,
      reason: `Blocked argument path ${entry.path} is present.`,
      matched_constraint: "blocked_argument_paths" as const,
      argument_path: entry.path,
      value_preview: previewValue(entry.value)
    }));
}

function evaluateRequiredBooleanFlags(constraints: PolicyConstraints, entries: ArgumentEntry[]): ConstraintFinding[] {
  return (constraints.required_boolean_flags ?? []).flatMap((flag) => {
    const entry = firstEntryForPath(entries, flag);
    if (!entry) {
      return [
        {
          status: "fail" as const,
          reason: `Required boolean flag ${flag}=true is missing.`,
          matched_constraint: "required_boolean_flags" as const,
          argument_path: flag
        }
      ];
    }

    if (entry.value !== true) {
      return [
        {
          status: "fail" as const,
          reason: `Required boolean flag ${entry.path} must be true.`,
          matched_constraint: "required_boolean_flags" as const,
          argument_path: entry.path,
          value_preview: previewValue(entry.value)
        }
      ];
    }

    return [];
  });
}

function evaluatePathPrefixes(constraints: PolicyConstraints, entries: ArgumentEntry[]): ConstraintFinding[] {
  if (!constraints.path_prefixes) {
    return [];
  }

  if (constraints.path_prefixes.length === 0) {
    return [constraintFailure("path_prefixes", "No allowed path prefixes are configured.")];
  }

  const pathEntries = entries.filter((entry) => typeof entry.value === "string" && isPathKey(entry.key));
  if (pathEntries.length === 0) {
    return [constraintFailure("path_prefixes", "No path-like argument was found for path prefix enforcement.")];
  }

  return pathEntries.flatMap((entry) => {
    const value = String(entry.value);
    const result = pathAllowedByPrefixes(value, constraints.path_prefixes ?? []);
    if (result.allowed) {
      return [];
    }
    return [
      {
        status: "fail" as const,
        reason: result.reason,
        matched_constraint: "path_prefixes" as const,
        argument_path: entry.path,
        value_preview: previewValue(value)
      }
    ];
  });
}

function evaluateDomainConstraints(constraints: PolicyConstraints, entries: ArgumentEntry[]): ConstraintFinding[] {
  const findings: ConstraintFinding[] = [];
  const domainEntries = entries
    .filter((entry) => typeof entry.value === "string" && isDomainKey(entry.key))
    .map((entry) => ({ entry, domain: domainFromValue(String(entry.value), entry.key) }));

  if (constraints.allowed_domains) {
    if (constraints.allowed_domains.length === 0) {
      if (domainEntries.length === 0) {
        findings.push(constraintFailure("allowed_domains", "No domain-like argument was found for domain allowlist enforcement."));
      } else {
        findings.push(
          ...domainEntries.map(({ entry }) => ({
            status: "fail" as const,
            reason: "No allowed domains are configured for this external sink.",
            matched_constraint: "allowed_domains" as const,
            argument_path: entry.path,
            value_preview: previewValue(entry.value)
          }))
        );
      }
    } else if (domainEntries.length === 0) {
      findings.push(constraintFailure("allowed_domains", "No domain-like argument was found for domain allowlist enforcement."));
    } else {
      for (const { entry, domain } of domainEntries) {
        if (!domain || !domainMatches(domain, constraints.allowed_domains)) {
          findings.push({
            status: "fail",
            reason: domain ? `Domain ${domain} is not in the allowlist.` : `Could not parse a domain from ${entry.path}.`,
            matched_constraint: "allowed_domains",
            argument_path: entry.path,
            value_preview: previewValue(entry.value)
          });
        }
      }
    }
  }

  if (constraints.blocked_domains && constraints.blocked_domains.length > 0) {
    for (const { entry, domain } of domainEntries) {
      if (domain && domainMatches(domain, constraints.blocked_domains)) {
        findings.push({
          status: "fail",
          reason: `Domain ${domain} is explicitly blocked.`,
          matched_constraint: "blocked_domains",
          argument_path: entry.path,
          value_preview: previewValue(entry.value)
        });
      }
    }
  }

  return findings;
}

function evaluateMaxAmount(constraints: PolicyConstraints, entries: ArgumentEntry[]): ConstraintFinding[] {
  if (constraints.max_amount === undefined) {
    return [];
  }

  const amountEntries = entries.filter((entry) => isAmountKey(entry.key));
  if (amountEntries.length === 0) {
    return [constraintFailure("max_amount", "No amount-like argument was found for maximum amount enforcement.")];
  }

  return amountEntries.flatMap((entry) => {
    const numeric = numericValue(entry.value);
    if (numeric === undefined) {
      return [
        {
          status: "fail" as const,
          reason: `Amount argument ${entry.path} is not numeric.`,
          matched_constraint: "max_amount" as const,
          argument_path: entry.path,
          value_preview: previewValue(entry.value)
        }
      ];
    }

    if (numeric > constraints.max_amount!) {
      return [
        {
          status: "fail" as const,
          reason: `Amount ${numeric} exceeds maximum allowed amount ${constraints.max_amount}.`,
          matched_constraint: "max_amount" as const,
          argument_path: entry.path,
          value_preview: previewValue(entry.value)
        }
      ];
    }

    return [];
  });
}

function evaluateBlockedPatterns(constraints: PolicyConstraints, entries: ArgumentEntry[]): ConstraintFinding[] {
  return (constraints.blocked_argument_patterns ?? []).flatMap((blocked) => {
    let regex: RegExp;
    try {
      regex = new RegExp(blocked.pattern, "i");
    } catch (error) {
      return [
        {
          status: "fail" as const,
          reason: `Invalid blocked argument regex for ${blocked.path}: ${error instanceof Error ? error.message : String(error)}`,
          matched_constraint: "blocked_argument_patterns" as const,
          argument_path: blocked.path
        }
      ];
    }

    return entriesForPath(entries, blocked.path).flatMap((entry) => {
      const value = typeof entry.value === "string" ? entry.value : JSON.stringify(entry.value);
      if (value && regex.test(value)) {
        return [
          {
            status: "fail" as const,
            reason: blocked.reason,
            matched_constraint: "blocked_argument_patterns" as const,
            argument_path: entry.path,
            value_preview: previewValue(entry.value)
          }
        ];
      }
      return [];
    });
  });
}

function collectArgumentEntries(value: unknown, prefix = ""): ArgumentEntry[] {
  if (value === null || value === undefined) {
    return [];
  }

  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectArgumentEntries(item, `${prefix}[${index}]`));
  }

  if (typeof value === "object") {
    const out: ArgumentEntry[] = [];
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = prefix ? `${prefix}.${key}` : key;
      out.push({ path: childPath, key, value: child });
      out.push(...collectArgumentEntries(child, childPath));
    }
    return out;
  }

  return prefix ? [{ path: prefix, key: lastPathSegment(prefix), value }] : [];
}

function hasArgumentPath(entries: ArgumentEntry[], path: string): boolean {
  return firstEntryForPath(entries, path) !== undefined;
}

function firstEntryForPath(entries: ArgumentEntry[], path: string): ArgumentEntry | undefined {
  return entriesForPath(entries, path)[0];
}

function entriesForPath(entries: ArgumentEntry[], path: string): ArgumentEntry[] {
  if (path === "*") {
    return entries;
  }

  const normalized = normalizeArgumentPath(path);
  const simple = !normalized.includes(".") && !normalized.includes("[");
  return entries.filter((entry) => {
    const entryPath = normalizeArgumentPath(entry.path);
    if (entryPath === normalized || entryPath.startsWith(`${normalized}.`) || entryPath.startsWith(`${normalized}[`)) {
      return true;
    }
    return simple && normalizeKey(entry.key) === normalizeKey(normalized);
  });
}

function normalizeArgumentPath(path: string): string {
  return path.trim().replace(/\[(\w+)\]/g, ".$1").replace(/^\./, "");
}

function lastPathSegment(path: string): string {
  return path.split(/[.\[\]]/).filter(Boolean).at(-1) ?? path;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function isPathKey(key: string): boolean {
  return PATH_KEYS.has(normalizeKey(key));
}

function isAmountKey(key: string): boolean {
  return AMOUNT_KEYS.has(normalizeKey(key));
}

function isDomainKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return DOMAIN_KEYS.has(normalized) || normalized.endsWith("url") || normalized.includes("webhook") || normalized.includes("endpoint");
}

function numericValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function domainFromValue(value: string, key: string): string | undefined {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) {
    return undefined;
  }

  const emailMatch = trimmed.match(/@([a-z0-9.-]+\.[a-z]{2,})\b/i);
  if (emailMatch?.[1]) {
    return cleanDomain(emailMatch[1]);
  }

  if (normalizeKey(key).includes("email")) {
    return undefined;
  }

  try {
    return cleanDomain(new URL(trimmed).hostname);
  } catch {
    try {
      return cleanDomain(new URL(`https://${trimmed}`).hostname);
    } catch {
      return undefined;
    }
  }
}

function cleanDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

function domainMatches(domain: string, patterns: string[]): boolean {
  const clean = cleanDomain(domain);
  return patterns.some((pattern) => {
    const allowed = cleanDomain(pattern);
    return clean === allowed || clean.endsWith(`.${allowed}`);
  });
}

function pathAllowedByPrefixes(value: string, prefixes: string[]): { allowed: boolean; reason: string } {
  const normalized = normalizePathValue(value);
  if (!normalized) {
    return { allowed: false, reason: "Path argument is empty." };
  }

  if (hasParentTraversal(normalized)) {
    return { allowed: false, reason: "Path argument contains parent directory traversal." };
  }

  if (normalized.startsWith("~")) {
    return { allowed: false, reason: "Home-relative paths are not allowed by path_prefixes." };
  }

  const isAbsolute = isAbsolutePath(normalized);
  for (const prefix of prefixes) {
    const normalizedPrefix = normalizePathValue(prefix);
    if (!normalizedPrefix) {
      continue;
    }

    const prefixIsAbsolute = isAbsolutePath(normalizedPrefix);
    if (isAbsolute && !prefixIsAbsolute) {
      continue;
    }

    if (prefixMatches(normalized, normalizedPrefix)) {
      return { allowed: true, reason: "Path prefix matched." };
    }
  }

  return { allowed: false, reason: `Path is outside allowed prefixes: ${prefixes.join(", ")}.` };
}

function normalizePathValue(value: string): string {
  return value.trim().replace(/^['"]|['"]$/g, "").replace(/\\/g, "/").replace(/\/+/g, "/");
}

function isAbsolutePath(value: string): boolean {
  return /^[a-z]:\//i.test(value) || value.startsWith("/");
}

function stripLeadingDotSlash(value: string): string {
  return value.replace(/^\.\//, "");
}

function hasParentTraversal(value: string): boolean {
  return stripLeadingDotSlash(value).split("/").includes("..");
}

function prefixMatches(value: string, prefix: string): boolean {
  if (prefix === "./") {
    return !isAbsolutePath(value);
  }

  const valueCandidates = new Set([value, stripLeadingDotSlash(value)]);
  const prefixCandidates = new Set([prefix, stripLeadingDotSlash(prefix)]);

  for (const candidate of valueCandidates) {
    for (const prefixCandidate of prefixCandidates) {
      const normalizedPrefix = prefixCandidate.endsWith("/") ? prefixCandidate : `${prefixCandidate}/`;
      if (candidate === prefixCandidate || candidate.startsWith(normalizedPrefix)) {
        return true;
      }
    }
  }

  return false;
}

function constraintFailure(matched_constraint: ConstraintFinding["matched_constraint"], reason: string): ConstraintFinding {
  return {
    status: "fail",
    reason,
    matched_constraint
  };
}

function previewValue(value: unknown): string {
  const raw = typeof value === "string" ? value : JSON.stringify(value);
  if (!raw) {
    return "";
  }
  return raw.length > 80 ? `${raw.slice(0, 77)}...` : raw;
}