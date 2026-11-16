#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { checkUrl, type PageReport } from "./check.js";
import { formatReport } from "./format.js";

const USAGE = `Usage: no-phone-home [options] <url>...

Fails when a page's Content-Security-Policy lets it contact a host other than
its own and the ones you allow: through fetch or WebSocket, scripts, images,
fonts, frames, workers, form submissions or violation reports.

Options:
  -a, --allow <host>     Allow this host too; "*.example.com" allows subdomains (repeatable)
      --timeout <ms>     Give up on a page after this long (default 30000)
      --json             Print the full reports as JSON
  -q, --quiet            Print nothing; use the exit code
  -h, --help             Show this help
  -v, --version          Show the version

Exit codes: 0 = every page passed, 1 = a page can contact another host, 2 = error.`;

function describeError(error: unknown): string {
  const failure = error as Error & { cause?: Error & { code?: string; errors?: Error[] } };
  if (failure.name === "TimeoutError") return "timed out";
  const cause = failure.cause;
  const detail = cause?.message || cause?.errors?.[0]?.message || cause?.code;
  return detail ? `${failure.message}: ${detail}` : failure.message || String(error);
}

async function main(): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        allow: { type: "string", short: "a", multiple: true },
        timeout: { type: "string", default: "30000" },
        json: { type: "boolean", default: false },
        quiet: { type: "boolean", short: "q", default: false },
        help: { type: "boolean", short: "h", default: false },
        version: { type: "boolean", short: "v", default: false },
      },
    });
  } catch (error) {
    console.error(`${(error as Error).message}\n\n${USAGE}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (values.version) {
    const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
    console.log(pkg.version);
    return 0;
  }
  const timeoutMs = Number(values.timeout);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    console.error(`--timeout must be a positive number of milliseconds, got "${values.timeout}"`);
    return 2;
  }
  if (positionals.length === 0) {
    console.error(USAGE);
    return 2;
  }

  const results: { url: string; report?: PageReport; error?: string }[] = [];
  for (const url of positionals) {
    if (!/^https?:\/\//i.test(url)) {
      results.push({ url, error: "expected an http:// or https:// URL" });
      continue;
    }
    try {
      results.push({ url, report: await checkUrl(url, { allow: values.allow ?? [], timeoutMs }) });
    } catch (error) {
      results.push({ url, error: describeError(error) });
    }
  }

  if (values.json) {
    console.log(JSON.stringify(results, null, 2));
  } else if (!values.quiet) {
    for (const r of results) console.log(r.report ? formatReport(r.report) : `${r.url}: ERROR: ${r.error}`);
  }
  if (results.some((r) => r.error)) return 2;
  return results.some((r) => !r.report!.ok) ? 1 : 0;
}

process.exitCode = await main();
