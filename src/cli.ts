#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { BrowserUnavailableError, openRecorder, type BrowserReport, type Recorder } from "./browser.js";
import { checkUrl, checkWorker, type PageReport, type WorkerKind, type WorkerReport } from "./check.js";
import { formatBrowserReport, formatReport, formatWorkerReport } from "./format.js";
import { serveDirectory, type ServedSite } from "./serve.js";

const USAGE = `Usage: no-phone-home [options] <url>...
       no-phone-home [options] --serve <folder>

Fails when a page's Content-Security-Policy lets it contact a host other than
its own and the ones you allow: through fetch or WebSocket, scripts, images,
fonts, frames, form submissions or violation reports. Workers run under the
policy of their own script, so each worker script is checked as well.

Options:
  -a, --allow <host>     Allow this host too; "*.example.com" allows subdomains (repeatable)
  -w, --worker <path>    Also check this worker script, resolved against each page (repeatable)
      --browser          Also load each page in headless Chromium, report every host it contacted,
                         and check the script of every worker it started
      --wait <ms>        With --browser, keep recording this long after the network goes idle (default 0)
      --timeout <ms>     Give up on a page after this long (default 30000); with --browser, it applies to each step
      --serve <folder>   Serve a static build folder locally and check every .html page in it
      --headers <file>   With --serve, the host's header rules: a vercel.json or a _headers file
                         (default: the folder's _headers file, if it has one)
      --json             Print the full reports as JSON
  -q, --quiet            Print nothing; use the exit code
  -h, --help             Show this help
  -v, --version          Show the version

Exit codes: 0 = every page passed, 1 = a page can contact another host, 2 = error.
With --browser, a page passes only when its policy passes and every request it
made in Chromium stayed on its own host and the allowed hosts.`;

function describeError(error: unknown): string {
  const failure = error as Error & { cause?: Error & { code?: string; errors?: Error[] } };
  if (failure.name === "TimeoutError") return "timed out";
  const cause = failure.cause;
  const detail = cause?.message || cause?.errors?.[0]?.message || cause?.code;
  return detail ? `${failure.message}: ${detail}` : failure.message || String(error);
}

const MAX_TIMER_MS = 2_147_483_647;

function positiveInteger(value: string | undefined, option: string, allowZero = false): number | string {
  const n = /^\d+$/.test(value ?? "") ? Number(value) : NaN;
  if (n <= MAX_TIMER_MS && (n > 0 || (allowZero && n === 0))) return n;
  return `${option} must be a ${allowZero ? "non-negative" : "positive"} whole number of milliseconds up to ${MAX_TIMER_MS}, got "${value}"`;
}

async function main(): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        allow: { type: "string", short: "a", multiple: true },
        worker: { type: "string", short: "w", multiple: true },
        browser: { type: "boolean", default: false },
        wait: { type: "string" },
        timeout: { type: "string", default: "30000" },
        serve: { type: "string" },
        headers: { type: "string" },
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
  const timeoutMs = positiveInteger(values.timeout, "--timeout");
  if (typeof timeoutMs === "string") {
    console.error(timeoutMs);
    return 2;
  }
  const waitMs = values.wait === undefined ? 0 : positiveInteger(values.wait, "--wait", true);
  if (typeof waitMs === "string") {
    console.error(waitMs);
    return 2;
  }
  if (values.wait !== undefined && !values.browser) {
    console.error("--wait only applies with --browser");
    return 2;
  }
  if (values.headers !== undefined && values.serve === undefined) {
    console.error("--headers only applies with --serve");
    return 2;
  }
  if (values.serve !== undefined && positionals.length > 0) {
    console.error("--serve checks the pages in a folder; pass either --serve or URLs, not both");
    return 2;
  }
  if (values.serve === undefined && positionals.length === 0) {
    console.error(USAGE);
    return 2;
  }
  for (const path of values.worker ?? []) {
    const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(path)?.[1]?.toLowerCase();
    if (!path.trim() || (scheme && (!["http", "https"].includes(scheme) || !URL.canParse(path)))) {
      console.error(`--worker must be a path or an http:// or https:// URL, got "${path}"`);
      return 2;
    }
  }

  let site: ServedSite | undefined;
  if (values.serve !== undefined) {
    try {
      site = await serveDirectory(values.serve, values.headers === undefined ? {} : { headers: values.headers });
    } catch (error) {
      console.error((error as Error).message);
      return 2;
    }
    if (site.pages.length === 0) {
      console.error(`${values.serve} has no .html files`);
      await site.close();
      return 2;
    }
    if (!values.quiet) {
      console.error(`Serving ${values.serve} at ${site.url}${site.config ? ` with the headers from ${site.config}` : ""}`);
      for (const note of site.notes) console.error(`note: ${note}`);
    }
  }
  const urls = site ? site.pages.map((path) => site.url + path) : positionals;

  let recorder: Recorder | undefined;
  if (values.browser) {
    try {
      recorder = await openRecorder();
    } catch (error) {
      console.error(error instanceof BrowserUnavailableError ? error.message : `Chromium failed to start: ${describeError(error)}`);
      await site?.close();
      return 2;
    }
  }

  const allow = values.allow ?? [];
  const results: Result[] = [];
  try {
    for (const url of urls) {
      if (!/^https?:\/\//i.test(url)) {
        results.push({ url, error: "expected an http:// or https:// URL" });
        continue;
      }
      try {
        const report = await checkUrl(url, { allow, timeoutMs });
        const browser = recorder ? await recorder.record(url, { allow, timeoutMs, waitMs }) : undefined;
        const found = [...(browser?.workers ?? []), ...(values.worker ?? []).map((path) => ({ url: new URL(path, report.finalUrl).href, kind: "worker" as const }))];
        const workers: WorkerResult[] = [];
        for (const { kind, url: href } of found) {
          const worker = { kind, url: href.replace(/#.*$/, "") };
          if (workers.some((w) => w.url === worker.url)) continue;
          try {
            workers.push({ url: worker.url, kind: worker.kind, report: await checkWorker(worker.url, worker.kind, { allow, timeoutMs }) });
          } catch (error) {
            workers.push({ url: worker.url, kind: worker.kind, error: describeError(error) });
          }
        }
        results.push({ url, report, ...(browser ? { browser } : {}), ...(workers.length ? { workers } : {}) });
      } catch (error) {
        results.push({ url, error: describeError(error) });
      }
    }
  } finally {
    await recorder?.close();
    await site?.close();
  }

  if (values.json) {
    console.log(JSON.stringify(results, null, 2));
  } else if (!values.quiet) {
    for (const r of results) {
      if (!r.report) {
        console.log(`${r.url}: ERROR: ${r.error}`);
        continue;
      }
      const parts = [formatReport(r.report), ...(r.browser ? [formatBrowserReport(r.browser)] : [])];
      for (const w of r.workers ?? []) parts.push(w.report ? formatWorkerReport(w.report) : `${w.url} (${w.kind}): ERROR: ${w.error}`);
      console.log(parts.join("\n"));
    }
    if (site) console.log(summary(results));
  }
  if (results.some(hasError)) return 2;
  return results.every(passed) ? 0 : 1;
}

function hasError(r: Result): boolean {
  return Boolean(r.error || r.workers?.some((w) => w.error));
}

function passed(r: Result): boolean {
  return r.report!.ok && r.browser?.ok !== false && !r.workers?.some((w) => !w.report!.ok);
}

function summary(results: Result[]): string {
  const errors = results.filter(hasError).length;
  const failed = results.filter((r) => !hasError(r) && !passed(r)).length;
  const pages = `${results.length} page${results.length === 1 ? "" : "s"}`;
  return `Checked ${pages}: ${results.length - failed - errors} passed, ${failed} failed${errors ? `, ${errors} with errors` : ""}`;
}

interface WorkerResult {
  url: string;
  kind: WorkerKind;
  report?: WorkerReport;
  error?: string;
}

interface Result {
  url: string;
  report?: PageReport;
  browser?: BrowserReport;
  workers?: WorkerResult[];
  error?: string;
}

process.exitCode = await main();
