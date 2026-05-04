import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { stringify as stringifyYaml } from "yaml";
import type { Command } from "commander";
import { compilePolicy, type CapabilityGraph } from "@mcp-capagate/core";

export function registerPolicyCommand(program: Command): void {
  program
    .command("policy")
    .description("Compile a least-privilege policy from a capability graph.")
    .requiredOption("-i, --input <path>", "capability graph JSON")
    .option("-o, --out <path>", "policy YAML output", "capagate.policy.yaml")
    .action(async (options: { input: string; out: string }) => {
      const graph = JSON.parse(await readFile(options.input, "utf8")) as CapabilityGraph;
      const policy = compilePolicy(graph);
      await mkdir(dirname(options.out), { recursive: true });
      await writeFile(options.out, stringifyYaml(policy), "utf8");
      console.log(`Policy written to ${options.out}`);
      console.log(`Policy hash: ${policy.policy_hash}`);
    });
}
