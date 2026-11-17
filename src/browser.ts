import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { Browser, BrowserContext, Request, WebSocket } from "playwright-core";
import { hostAllowList } from "./csp.js";

export interface RecordOptions {
  allow?: string[];
  timeoutMs?: number;
  waitMs?: number;
}

export interface RecordedRequest {
  url: string;
  host: string;
  type: string;
  from: "page" | "service worker";
  blocked?: "csp";
  error?: string;
}

export interface HostActivity {
  host: string;
  requests: number;
  types: Record<string, number>;
  failed: number;
}

export interface BrowserReport {
  url: string;
  finalUrl: string;
  status: number | null;
  ok: boolean;
  contacted: HostActivity[];
  blocked: HostActivity[];
  requests: RecordedRequest[];
  notes: string[];
}

export interface Recorder {
  record(url: string, options?: RecordOptions): Promise<BrowserReport>;
  close(): Promise<void>;
}

export class BrowserUnavailableError extends Error {
  override name = "BrowserUnavailableError";
}

const VIOLATION_BINDING = "__noPhoneHomeViolation";

const VIOLATION_LISTENER = `document.addEventListener("securitypolicyviolation", (event) => {
  if (event.disposition === "enforce") globalThis.${VIOLATION_BINDING}({ url: event.blockedURI, directive: event.effectiveDirective });
}, true);`;

const TYPE_NAMES: Record<string, string> = { ping: "beacon" };

const NETWORK_PROTOCOLS = new Set(["http:", "https:", "ws:", "wss:"]);

function networkHost(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return NETWORK_PROTOCOLS.has(parsed.protocol) ? parsed.hostname.toLowerCase() : undefined;
  } catch {
    return undefined;
  }
}

function requestType(request: Request): string {
  const type = request.resourceType();
  if (type !== "document") return TYPE_NAMES[type] ?? type;
  try {
    return request.frame().parentFrame() ? "frame" : "page";
  } catch {
    return "page";
  }
}

function firstLine(error: unknown): Error {
  const original = error as Error;
  const wrapped = new Error((original.message ?? String(error)).split("\n")[0]!.replace(/^[a-zA-Z.]+: /, ""));
  wrapped.name = original.name ?? "Error";
  return wrapped;
}

function ownVersion(): string {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  return pkg.optionalDependencies?.["playwright-core"] ?? "latest";
}

function installCommand(withDeps: boolean): string {
  let version = ownVersion();
  try {
    version = createRequire(import.meta.url)("playwright-core/package.json").version;
  } catch {}
  return `npx playwright-core@${version} install ${withDeps ? "--with-deps " : ""}chromium`;
}

async function launch(): Promise<Browser> {
  let chromium;
  try {
    ({ chromium } = await import("playwright-core"));
  } catch (error) {
    if ((error as { code?: string }).code !== "ERR_MODULE_NOT_FOUND") throw error;
    throw new BrowserUnavailableError(
      `--browser needs the playwright-core package, which is not installed. Install it with: npm install playwright-core@${ownVersion()}, then: ${installCommand(false)}`,
    );
  }
  try {
    return await chromium.launch();
  } catch (error) {
    const message = (error as Error).message ?? "";
    if (message.includes("Executable doesn't exist")) {
      throw new BrowserUnavailableError(`--browser needs Chromium for Playwright, which is not installed. Install it with: ${installCommand(false)}`);
    }
    if (message.includes("missing dependencies")) {
      throw new BrowserUnavailableError(`Chromium cannot start because system libraries are missing. Install them with: ${installCommand(true)}`);
    }
    throw firstLine(error);
  }
}

function summarize(requests: RecordedRequest[]): HostActivity[] {
  const byHost = new Map<string, HostActivity>();
  for (const request of requests) {
    let activity = byHost.get(request.host);
    if (!activity) byHost.set(request.host, (activity = { host: request.host, requests: 0, types: {}, failed: 0 }));
    const type = request.from === "service worker" ? `${request.type} from a service worker` : request.type;
    activity.requests++;
    activity.types[type] = (activity.types[type] ?? 0) + 1;
    if (request.error) activity.failed++;
  }
  return [...byHost.values()].sort((a, b) => b.requests - a.requests || a.host.localeCompare(b.host));
}

function mergeViolations(requests: RecordedRequest[], violations: { url: string; directive: string }[]): RecordedRequest[] {
  const unmatched = requests.filter((request) => request.blocked === "csp");
  const merged = [...requests];
  for (const violation of violations) {
    const host = networkHost(violation.url);
    if (host === undefined) continue;
    const match = unmatched.findIndex((request) => request.url === violation.url);
    if (match >= 0) {
      unmatched.splice(match, 1);
      continue;
    }
    merged.push({ url: violation.url, host, type: violation.directive, from: "page", blocked: "csp" });
  }
  return merged;
}

async function recordInContext(context: BrowserContext, url: string, options: RecordOptions): Promise<BrowserReport> {
  const timeout = options.timeoutMs ?? 30_000;
  const seen = new Map<Request, RecordedRequest>();
  const sockets: RecordedRequest[] = [];
  const violations: { url: string; directive: string }[] = [];
  const notes: string[] = [];

  await context.exposeBinding(VIOLATION_BINDING, (_source, violation: { url: string; directive: string }) => {
    violations.push({ url: String(violation.url), directive: String(violation.directive) });
  });
  await context.addInitScript({ content: VIOLATION_LISTENER });

  context.on("request", (request) => {
    const host = networkHost(request.url());
    if (host === undefined) return;
    seen.set(request, { url: request.url(), host, type: requestType(request), from: request.serviceWorker() ? "service worker" : "page" });
  });
  context.on("requestfailed", (request) => {
    const recorded = seen.get(request);
    const failure = request.failure()?.errorText ?? "failed";
    if (!recorded) return;
    if (failure === "csp") recorded.blocked = "csp";
    else recorded.error = failure;
  });
  const watchSockets = (socket: WebSocket) => {
    const host = networkHost(socket.url());
    if (host === undefined) return;
    const recorded: RecordedRequest = { url: socket.url(), host, type: "websocket", from: "page" };
    sockets.push(recorded);
    socket.on("socketerror", (error) => (recorded.error = error));
  };
  context.on("page", (page) => page.on("websocket", watchSockets));

  const page = await context.newPage();
  let response;
  try {
    response = await page.goto(url, { waitUntil: "load", timeout });
  } catch (error) {
    throw firstLine(error);
  }
  try {
    await page.waitForLoadState("networkidle", { timeout });
  } catch {
    notes.push(
      `Chromium didn't report the network as idle within ${timeout} ms of the page loading, so recording stopped there (a redirect the policy blocked, or a shared worker, can cause this)`,
    );
  }
  if (options.waitMs) await page.waitForTimeout(options.waitMs);

  const finalUrl = response?.url() ?? page.url();
  const requestedHost = networkHost(url);
  const allowed = hostAllowList(finalUrl, options.allow ?? []);
  const requests = mergeViolations([...seen.values(), ...sockets], violations);
  const others = requests.filter((request) => request.host !== requestedHost && !allowed(request.host));
  const contacted = summarize(others.filter((request) => !request.blocked));

  return {
    url,
    finalUrl,
    status: response?.status() ?? null,
    ok: contacted.length === 0,
    contacted,
    blocked: summarize(others.filter((request) => request.blocked)),
    requests,
    notes,
  };
}

export async function openRecorder(): Promise<Recorder> {
  const browser = await launch();
  return {
    async record(url, options = {}) {
      const context = await browser.newContext();
      try {
        return await recordInContext(context, url, options);
      } finally {
        await context.close();
      }
    },
    close: () => browser.close(),
  };
}

export async function recordUrl(url: string, options: RecordOptions = {}): Promise<BrowserReport> {
  const recorder = await openRecorder();
  try {
    return await recorder.record(url, options);
  } finally {
    await recorder.close();
  }
}
