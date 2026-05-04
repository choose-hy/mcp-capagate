import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { Command } from "commander";
import { normalizeToolDefinitions } from "@mcp-capagate/core";

export function registerDiscoverCommand(program: Command): void {
  program
    .command("discover")
    .description("Normalize a local tools/list response or tools JSON array.")
    .requiredOption("-i, --input <path>", "input JSON")
    .option("-o, --out <path>", "normalized tools JSON")
    .action(async (options: { input: string; out?: string }) => {
      const raw = JSON.parse(await readFile(options.input, "utf8")) as unknown;
      const tools = normalizeToolDefinitions(raw);
      const output = `${JSON.stringify(tools, null, 2)}\n`;
      if (options.out) {
        await mkdir(dirname(options.out), { recursive: true });
        await writeFile(options.out, output, "utf8");
      } else {
        process.stdout.write(output);
      }
    });
}
