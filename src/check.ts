import { evaluatePolicies, parsePolicyList, parseReportingEndpoints, type Finding, type Policy } from "./csp.js";
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
