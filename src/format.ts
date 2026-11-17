import type { BrowserReport, HostActivity } from "./browser.js";
import type { PageReport } from "./check.js";
import { ANY_HOST, type Finding } from "./csp.js";

const SHOWN_HOSTS = 4;

function quoteVia(via: string[]): string {
  return via.map((v) => (v.startsWith("no ") ? v : `"${v}"`)).join(", ");
}

function hostList(findings: Finding[]): string {
  const any = findings.find((f) => f.reaches === ANY_HOST);
  if (any) return `any host, via ${quoteVia(any.via)}`;
  const hosts = findings.map((f) => f.reaches);
  if (hosts.length <= SHOWN_HOSTS) return hosts.join(", ");
  return `${hosts.slice(0, SHOWN_HOSTS).join(", ")} and ${hosts.length - SHOWN_HOSTS} more`;
}

export function formatReport(report: PageReport): string {
  const origin = new URL(report.finalUrl).host;
  const lines: string[] = [];
  const shown = report.finalUrl === report.url ? report.url : `${report.url} -> ${report.finalUrl}`;

  if (report.ok) {
    lines.push(`${shown}: PASS: the Content-Security-Policy keeps every request on ${origin} and the allowed hosts`);
  } else if (report.policies.length === 0) {
    lines.push(`${shown}: FAIL: no Content-Security-Policy is enforced, so the page can contact any host`);
  } else {
    lines.push(`${shown}: FAIL: the page can contact hosts outside the allowlist`);
    const byDirective = new Map<string, Finding[]>();
    for (const finding of report.findings) byDirective.set(finding.directive, [...(byDirective.get(finding.directive) ?? []), finding]);
    for (const [directive, findings] of byDirective) {
      lines.push(`  ${directive} (${findings[0]!.governs}): ${hostList(findings)}`);
    }
  }
  if (report.status >= 400) lines.push(`  note: the server answered HTTP ${report.status}`);
  for (const text of report.reportOnly) lines.push(`  note: report-only policy is not enforced: ${text}`);
  for (const warning of report.warnings) lines.push(`  warning: ${warning}`);
  return lines.join("\n");
}

function count(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function activity(host: HostActivity): string {
  const types = Object.entries(host.types)
    .sort(([, a], [, b]) => b - a)
    .map(([type, n]) => `${n} ${type}`);
  if (host.failed) types.push(`${host.failed} failed`);
  return `${host.host}: ${count(host.requests, "request")} (${types.join(", ")})`;
}

export function formatBrowserReport(report: BrowserReport): string {
  const origin = new URL(report.finalUrl).host;
  const lines: string[] = [];
  const shown = report.finalUrl === report.url ? report.url : `${report.url} -> ${report.finalUrl}`;
  const sent = report.requests.filter((request) => !request.blocked).length;

  if (report.ok) {
    lines.push(`${shown}: PASS: in Chromium, every request stayed on ${origin} and the allowed hosts (${count(sent, "request")})`);
  } else {
    lines.push(`${shown}: FAIL: in Chromium, the page contacted ${count(report.contacted.length, "other host")}`);
    for (const host of report.contacted) lines.push(`  ${activity(host)}`);
  }
  for (const host of report.blocked) lines.push(`  blocked by the Content-Security-Policy, never sent: ${activity(host)}`);
  if (report.status !== null && report.status >= 400) lines.push(`  note: the server answered HTTP ${report.status}`);
  for (const note of report.notes) lines.push(`  note: ${note}`);
  return lines.join("\n");
}
