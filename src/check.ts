import { evaluatePolicies, parsePolicyList, parseReportingEndpoints, WORKER_DIRECTIVES, type Finding, type Policy } from "./csp.js";
import { metaPolicies } from "./page.js";

export interface CheckOptions {
  allow?: string[];
  timeoutMs?: number;
}

export interface PageReport {
  url: string;
  finalUrl: string;
  status: number;
  ok: boolean;
  policies: { source: Policy["source"]; text: string }[];
  reportOnly: string[];
  findings: Finding[];
  warnings: string[];
}

export interface PageResponse {
  url: string;
  finalUrl: string;
  status: number;
  headers: Headers;
  html?: string;
}

export function checkResponse(response: PageResponse, options: CheckOptions = {}): PageReport {
  const policies = parsePolicyList(response.headers.get("content-security-policy") ?? "", "header");
  const warnings: string[] = [];

  for (const meta of response.html ? metaPolicies(response.html) : []) {
    if (!meta.inHead) {
      warnings.push("A <meta> Content-Security-Policy outside <head> is ignored by browsers.");
      continue;
    }
    if (meta.after) {
      warnings.push(`The <meta> Content-Security-Policy comes after ${meta.after}, which loads before the policy applies.`);
    }
    policies.push(...parsePolicyList(meta.content, "meta"));
  }

  const reportOnly = parsePolicyList(response.headers.get("content-security-policy-report-only") ?? "", "header").map(
    (policy) => policy.text,
  );

  const findings = evaluatePolicies(policies, {
    pageUrl: response.finalUrl,
    allow: options.allow ?? [],
    reportingEndpoints: parseReportingEndpoints(response.headers.get("reporting-endpoints")),
  });

  return {
    url: response.url,
    finalUrl: response.finalUrl,
    status: response.status,
    ok: findings.length === 0,
    policies: policies.map((policy) => ({ source: policy.source, text: policy.text })),
    reportOnly,
    findings,
    warnings,
  };
}

export type WorkerKind = "worker" | "shared worker" | "service worker";

export interface WorkerReport {
  url: string;
  kind: WorkerKind;
  finalUrl: string;
  status: number;
  ok: boolean;
  policies: { source: Policy["source"]; text: string }[];
  reportOnly: string[];
  findings: Finding[];
}

export function checkWorkerResponse(response: PageResponse, kind: WorkerKind, options: CheckOptions = {}): WorkerReport {
  const policies = parsePolicyList(response.headers.get("content-security-policy") ?? "", "header");
  const findings = evaluatePolicies(policies, {
    pageUrl: response.finalUrl,
    allow: options.allow ?? [],
    reportingEndpoints: parseReportingEndpoints(response.headers.get("reporting-endpoints")),
    directives: WORKER_DIRECTIVES,
  });
  return {
    url: response.url,
    kind,
    finalUrl: response.finalUrl,
    status: response.status,
    ok: findings.length === 0,
    policies: policies.map((policy) => ({ source: policy.source, text: policy.text })),
    reportOnly: parsePolicyList(response.headers.get("content-security-policy-report-only") ?? "", "header").map((policy) => policy.text),
    findings,
  };
}

const JAVASCRIPT_TYPES = new Set([
  "application/ecmascript",
  "application/javascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/javascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
]);

export async function checkWorker(url: string, kind: WorkerKind, options: CheckOptions = {}): Promise<WorkerReport> {
  const serviceWorker = kind === "service worker";
  const response = await fetch(url, {
    redirect: serviceWorker ? "manual" : "follow",
    headers: { accept: "*/*", ...(serviceWorker ? { "service-worker": "script" } : {}) },
    signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
  });
  await response.body?.cancel();
  const finalUrl = response.url || url;
  if (serviceWorker && response.status >= 300 && response.status < 400) {
    throw new Error("the service worker script redirects, and browsers don't run a redirected service worker script");
  }
  if (response.status >= 400) throw new Error(`the server answered HTTP ${response.status}`);
  if (new URL(finalUrl).origin !== new URL(url).origin) {
    throw new Error(`the script redirects to ${new URL(finalUrl).origin}, and browsers don't run a worker from another origin`);
  }
  const type = (response.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (serviceWorker && !JAVASCRIPT_TYPES.has(type)) {
    throw new Error(`a service worker script must be served as JavaScript, and this one is served as "${type}"`);
  }
  if (type.includes("html")) throw new Error(`the server answered with a "${type}" page, not a script`);
  return checkWorkerResponse({ url, finalUrl, status: response.status, headers: response.headers }, kind, options);
}

export async function checkUrl(url: string, options: CheckOptions = {}): Promise<PageReport> {
  const response = await fetch(url, {
    redirect: "follow",
    headers: { accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" },
    signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
  });
  const contentType = response.headers.get("content-type") ?? "";
  const html = /html/i.test(contentType) ? await response.text() : undefined;
  if (html === undefined) await response.body?.cancel();
  return checkResponse(
    { url, finalUrl: response.url || url, status: response.status, headers: response.headers, ...(html === undefined ? {} : { html }) },
    options,
  );
}
