import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../dist/cli.js", import.meta.url));

export interface RunResult {
  code: number | null;
  out: string;
  err: string;
}

export function runCli(args: string[], env: NodeJS.ProcessEnv = process.env): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = execFile(process.execPath, [cli, ...args], { encoding: "utf8", env }, (_error, out, err) => {
      resolve({ code: child.exitCode, out, err });
    });
  });
}
