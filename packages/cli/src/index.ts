#!/usr/bin/env node
import { Command } from "commander";
import { registerDemoCommand } from "./commands/demo.js";
import { registerDiffCommand } from "./commands/diff.js";
import { registerDiscoverCommand } from "./commands/discover.js";
import { registerInitCommand } from "./commands/init.js";
import { registerPolicyCommand } from "./commands/policy.js";
import { registerReportCommand } from "./commands/report.js";
import { registerScanCommand } from "./commands/scan.js";
import { registerWrapCommand } from "./commands/wrap.js";

const program = new Command();

program
  .name("capagate")
  .description("Capability-aware firewall and policy compiler for MCP tool calls.")
  .version("0.1.0");

registerInitCommand(program);
registerDiscoverCommand(program);
registerScanCommand(program);
registerPolicyCommand(program);
registerDiffCommand(program);
registerWrapCommand(program);
registerReportCommand(program);
registerDemoCommand(program);

await program.parseAsync(process.argv);
