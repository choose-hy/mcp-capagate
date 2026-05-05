import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { AttackChainDetector } from "../attackChain/detector.js";
import { TaintTracker } from "../attackChain/taint.js";
import { buildCapabilityGraph } from "../capability/graph.js";
import { createBaseline } from "../drift/baseline.js";
import { diffCapabilityGraphs, driftReportShouldFail } from "../drift/diff.js";
import { compilePolicy } from "../policy/compiler.js";
import { evaluatePolicy } from "../policy/evaluator.js";
import { normalizeToolDefinitions } from "../schema.js";
import { collectScanFindings } from "../scan/collector.js";
import type { Capability, CapabilityGraph, DriftFinding, MCPToolDefinition, PolicyDecisionName, RiskLevel, ScanFinding } from "../types.js";

export interface BenchmarkToolExpectation {
  tool: string;
  server?: string;
  capabilities?: Capability[];
  risk_level?: RiskLevel;
  policy_decision?: PolicyDecisionName;
  arguments?: unknown;
}

export interface BenchmarkAttackChainExpectation {
  sequence: Array<{ tool: string; server?: string; arguments?: unknown }>;
  expected_decision: PolicyDecisionName;
  expected_finding_types?: ScanFinding["type"][];
}

export interface BenchmarkDriftExpectation {
  expected_findings: DriftFinding["type"][];
  expected_should_fail: boolean;
}

export interface BenchmarkExpected {
  scenario: string;
  description?: string;
  checks: BenchmarkToolExpectation[];
  scanner_findings: ScanFinding["type"][];
  attack_chain?: BenchmarkAttackChainExpectation;
  drift?: BenchmarkDriftExpectation;
}

export interface BenchmarkCheckResult {
  type: "capability" | "risk" | "policy" | "scanner" | "attack_chain" | "drift";
  passed: boolean;
  message: string;
  expected?: unknown;
  actual?: unknown;
}

export interface BenchmarkScenarioResult {
  scenario: string;
  description?: string;
  passed: boolean;
  checks: BenchmarkCheckResult[];
  actual: {
    tools: string[];
    finding_types: ScanFinding["type"][];
    graph_hash: string;
  };
}

export interface BenchmarkMetrics {
  scenario_count: number;
  passed_scenarios: number;
  scenario_pass_rate: number;
  capability_match_rate: number;
  policy_decision_match_rate: number;
  scanner_finding_match_rate: number;
  false_positive_count: number;
  false_negative_count: number;
}

export interface BenchmarkReport {
  generated_at: string;
  suite: string;
  metrics: BenchmarkMetrics;
  scenarios: BenchmarkScenarioResult[];
}

interface FixtureToolsFile {
  tools?: unknown;
  baseline?: unknown;
}

export async function runBenchmarkSuite(suitePath: string): Promise<BenchmarkReport> {
  const entries = await readdir(suitePath, { withFileTypes: true });
  const scenarioDirs = entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  const scenarios = [];
  for (const scenario of scenarioDirs) {
    scenarios.push(await runBenchmarkScenario(join(suitePath, scenario)));
  }
  return {
    generated_at: new Date().toISOString(),
    suite: suitePath,
    metrics: computeMetrics(scenarios),
    scenarios
  };
}

export async function runBenchmarkScenario(scenarioPath: string): Promise<BenchmarkScenarioResult> {
  const toolsRaw = JSON.parse(await readFile(join(scenarioPath, "tools.json"), "utf8")) as unknown;
  const expected = JSON.parse(await readFile(join(scenarioPath, "expected.json"), "utf8")) as BenchmarkExpected;
  const tools = loadCurrentTools(toolsRaw, expected.scenario);
  const graph = buildGraph(tools, expected.scenario);
  const policy = compilePolicy(graph);
  const checks: BenchmarkCheckResult[] = [];

  for (const expectation of expected.checks) {
    const node = findNode(graph, expectation.tool, expectation.server);
    if (!node) {
      checks.push({
        type: "capability",
        passed: false,
        message: `Tool ${toolKey(expectation.tool, expectation.server)} was not found.`,
        expected: expectation,
        actual: null
      });
      continue;
    }

    if (expectation.capabilities) {
      const missing = expectation.capabilities.filter((capability) => !node.capabilities.includes(capability));
      checks.push({
        type: "capability",
        passed: missing.length === 0,
        message: missing.length === 0 ? `${node.tool} contains expected capabilities.` : `${node.tool} missed capabilities: ${missing.join(", ")}.`,
        expected: expectation.capabilities,
        actual: node.capabilities
      });
    }

    if (expectation.risk_level) {
      checks.push({
        type: "risk",
        passed: node.risk_level === expectation.risk_level,
        message: `${node.tool} risk is ${node.risk_level}; expected ${expectation.risk_level}.`,
        expected: expectation.risk_level,
        actual: node.risk_level
      });
    }

    if (expectation.policy_decision) {
      const decision = evaluatePolicy(policy, {
        tool: node.tool,
        server: node.server,
        arguments: expectation.arguments,
        capabilityNode: node
      });
      checks.push({
        type: "policy",
        passed: decision.decision === expectation.policy_decision,
        message: `${node.tool} policy decision is ${decision.decision}; expected ${expectation.policy_decision}.`,
        expected: expectation.policy_decision,
        actual: decision.decision
      });
    }
  }

  checks.push(scannerCheck(expected.scanner_findings, graph.findings ?? []));

  if (expected.attack_chain) {
    checks.push(attackChainCheck(graph, expected.attack_chain));
  }

  if (expected.drift) {
    checks.push(driftCheck(toolsRaw, expected));
  }

  return {
    scenario: expected.scenario,
    description: expected.description,
    passed: checks.every((check) => check.passed),
    checks,
    actual: {
      tools: graph.nodes.map((node) => toolKey(node.tool, node.server)),
      finding_types: [...new Set((graph.findings ?? []).map((finding) => finding.type))].sort(),
      graph_hash: graph.graph_hash
    }
  };
}

export function renderBenchmarkMarkdown(report: BenchmarkReport): string {
  const lines = [
    "# MCP Tool Risk Benchmark",
    "",
    `Generated: ${report.generated_at}`,
    `Suite: \`${report.suite}\``,
    "",
    "## Summary",
    "",
    `- Scenarios: ${report.metrics.passed_scenarios}/${report.metrics.scenario_count}`,
    `- Scenario pass rate: ${percent(report.metrics.scenario_pass_rate)}`,
    `- Capability match rate: ${percent(report.metrics.capability_match_rate)}`,
    `- Policy decision match rate: ${percent(report.metrics.policy_decision_match_rate)}`,
    `- Scanner finding match rate: ${percent(report.metrics.scanner_finding_match_rate)}`,
    `- False positives: ${report.metrics.false_positive_count}`,
    `- False negatives: ${report.metrics.false_negative_count}`,
    "",
    "## Scenarios",
    "",
    "| Scenario | Result | Failed checks |",
    "| --- | --- | --- |"
  ];

  for (const scenario of report.scenarios) {
    const failed = scenario.checks.filter((check) => !check.passed).map((check) => `${check.type}: ${check.message}`);
    lines.push(`| ${scenario.scenario} | ${scenario.passed ? "PASS" : "FAIL"} | ${failed.length === 0 ? "-" : failed.join("<br>")} |`);
  }

  return `${lines.join("\n")}\n`;
}

function buildGraph(tools: MCPToolDefinition[], source: string): CapabilityGraph {
  const graphWithoutFindings = buildCapabilityGraph(tools, source);
  const findings = collectScanFindings(tools, graphWithoutFindings.nodes);
  return buildCapabilityGraph(tools, source, findings);
}

function loadCurrentTools(raw: unknown, scenario: string): MCPToolDefinition[] {
  if (raw && typeof raw === "object" && !Array.isArray(raw) && Array.isArray((raw as FixtureToolsFile).tools)) {
    return normalizeToolDefinitions((raw as FixtureToolsFile).tools, scenario);
  }
  return normalizeToolDefinitions(raw, scenario);
}

function loadBaselineTools(raw: unknown, scenario: string): MCPToolDefinition[] {
  if (raw && typeof raw === "object" && !Array.isArray(raw) && (raw as FixtureToolsFile).baseline) {
    return normalizeToolDefinitions((raw as FixtureToolsFile).baseline, scenario);
  }
  throw new Error(`Scenario ${scenario} expects drift baseline data in tools.json.`);
}

function findNode(graph: CapabilityGraph, tool: string, server?: string) {
  return graph.nodes.find((node) => node.tool === tool && (!server || node.server === server));
}

function scannerCheck(expectedTypes: ScanFinding["type"][], actualFindings: ScanFinding[]): BenchmarkCheckResult {
  const actualTypes = [...new Set(actualFindings.map((finding) => finding.type))].sort();
  const missing = expectedTypes.filter((type) => !actualTypes.includes(type));
  const unexpected = expectedTypes.length === 0 ? actualTypes : [];
  return {
    type: "scanner",
    passed: missing.length === 0 && unexpected.length === 0,
    message:
      missing.length === 0 && unexpected.length === 0
        ? "Scanner findings matched expectation."
        : `Missing findings: ${missing.join(", ") || "-"}; unexpected findings: ${unexpected.join(", ") || "-"}.`,
    expected: expectedTypes,
    actual: actualTypes
  };
}

function attackChainCheck(graph: CapabilityGraph, expectation: BenchmarkAttackChainExpectation): BenchmarkCheckResult {
  const detector = new AttackChainDetector();
  const taintTracker = new TaintTracker();
  let actualDecision: PolicyDecisionName = "allow";
  const findingTypes = new Set<ScanFinding["type"]>();

  for (const call of expectation.sequence) {
    const node = findNode(graph, call.tool, call.server);
    if (!node) {
      actualDecision = "block";
      continue;
    }
    const event = {
      session_id: "benchmark",
      tool: node.tool,
      server: node.server,
      capabilities: node.capabilities,
      data_sensitivity: node.data_sensitivity,
      arguments: call.arguments
    };
    const attackDecision = detector.evaluateCall(event);
    if (attackDecision.finding) {
      findingTypes.add(attackDecision.finding.type);
    }
    const taintDecision = taintTracker.evaluateCall(event);
    for (const finding of taintDecision.findings) {
      findingTypes.add(finding.type);
    }
    if (taintDecision.source_taint_labels.length > 0) {
      taintTracker.recordCallSource(event);
    }
    actualDecision = strongestDecision(actualDecision, attackDecision.decision, taintDecision.decision);
  }

  const findingTypesActual = [...findingTypes].sort();
  const missingFindings = (expectation.expected_finding_types ?? []).filter((type) => !findingTypesActual.includes(type));
  const passed = actualDecision === expectation.expected_decision && missingFindings.length === 0;
  return {
    type: "attack_chain",
    passed,
    message: `Attack-chain decision is ${actualDecision}; expected ${expectation.expected_decision}.`,
    expected: expectation,
    actual: { decision: actualDecision, finding_types: findingTypesActual }
  };
}

function driftCheck(raw: unknown, expected: BenchmarkExpected): BenchmarkCheckResult {
  const baseline = buildGraph(loadBaselineTools(raw, expected.scenario), `${expected.scenario}-baseline`);
  const current = buildGraph(loadCurrentTools(raw, expected.scenario), expected.scenario);
  const report = diffCapabilityGraphs(createBaseline(baseline).graph, current);
  const shouldFail = driftReportShouldFail(report, "high");
  const actualTypes = [...new Set(report.findings.map((finding) => finding.type))].sort();
  const expectedDrift = expected.drift!;
  const missing = expectedDrift.expected_findings.filter((type) => !actualTypes.includes(type));
  const passed = missing.length === 0 && shouldFail === expectedDrift.expected_should_fail;
  return {
    type: "drift",
    passed,
    message: `Drift should_fail is ${shouldFail}; expected ${expectedDrift.expected_should_fail}.`,
    expected: expectedDrift,
    actual: { finding_types: actualTypes, should_fail: shouldFail }
  };
}

function computeMetrics(scenarios: BenchmarkScenarioResult[]): BenchmarkMetrics {
  let expectedCapabilities = 0;
  let matchedCapabilities = 0;
  let expectedPolicies = 0;
  let matchedPolicies = 0;
  let expectedScannerFindings = 0;
  let matchedScannerFindings = 0;
  let falsePositiveCount = 0;
  let falseNegativeCount = 0;

  for (const scenario of scenarios) {
    for (const check of scenario.checks) {
      if (check.type === "capability") {
        const expected = Array.isArray(check.expected) ? check.expected.length : 0;
        const actual = Array.isArray(check.actual) ? check.actual : [];
        expectedCapabilities += expected;
        matchedCapabilities += Array.isArray(check.expected) ? check.expected.filter((item) => actual.includes(item)).length : 0;
      }
      if (check.type === "policy") {
        expectedPolicies += 1;
        matchedPolicies += check.passed ? 1 : 0;
      }
      if (check.type === "scanner") {
        const expected = Array.isArray(check.expected) ? check.expected : [];
        const actual = Array.isArray(check.actual) ? check.actual : [];
        expectedScannerFindings += expected.length;
        matchedScannerFindings += expected.filter((item) => actual.includes(item)).length;
        if (expected.length === 0 && actual.length > 0) {
          falsePositiveCount += actual.length;
        }
      }
      if (!check.passed) {
        falseNegativeCount += 1;
      }
    }
  }

  const passedScenarios = scenarios.filter((scenario) => scenario.passed).length;
  return {
    scenario_count: scenarios.length,
    passed_scenarios: passedScenarios,
    scenario_pass_rate: ratio(passedScenarios, scenarios.length),
    capability_match_rate: ratio(matchedCapabilities, expectedCapabilities),
    policy_decision_match_rate: ratio(matchedPolicies, expectedPolicies),
    scanner_finding_match_rate: ratio(matchedScannerFindings, expectedScannerFindings),
    false_positive_count: falsePositiveCount,
    false_negative_count: falseNegativeCount
  };
}

function strongestDecision(...decisions: PolicyDecisionName[]): PolicyDecisionName {
  const rank: Record<PolicyDecisionName, number> = { allow: 1, warn: 2, require_approval: 3, block: 4 };
  return decisions.sort((a, b) => rank[b] - rank[a])[0] ?? "allow";
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 1 : Number((numerator / denominator).toFixed(4));
}

function percent(value: number): string {
  return `${Math.round(value * 1000) / 10}%`;
}

function toolKey(tool: string, server?: string): string {
  return server ? `${server}:${tool}` : tool;
}
