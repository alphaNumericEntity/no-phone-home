export type PolicySource = "header" | "meta";

export interface Policy {
  source: PolicySource;
  text: string;
  directives: Map<string, string[]>;
}

export const ANY_HOST = "any host";

export interface Finding {
  directive: string;
  governs: string;
  reaches: string;
  via: string[];
}

export interface CheckedDirective {
  name: string;
  chain: string[];
  governs: string;
}

export interface EvaluateOptions {
  pageUrl: string;
  allow?: string[];
  reportingEndpoints?: Map<string, string>;
  directives?: CheckedDirective[];
}

const META_IGNORED = new Set(["report-uri", "report-to", "frame-ancestors", "sandbox"]);

const NETWORK_SCHEMES = new Set(["http", "https", "ws", "wss", "ftp"]);

const SCRIPT_DIRECTIVES = new Set(["script-src-elem", "script-src", "default-src"]);

const WORKER_SRC_CHAIN = ["worker-src", "child-src", "script-src", "default-src"];

export const CHECKED_DIRECTIVES: CheckedDirective[] = [
  { name: "connect-src", chain: ["connect-src", "default-src"], governs: "fetch, XHR, WebSocket, EventSource and sendBeacon" },
  { name: "script-src-elem", chain: ["script-src-elem", "script-src", "default-src"], governs: "scripts" },
  { name: "style-src-elem", chain: ["style-src-elem", "style-src", "default-src"], governs: "stylesheets" },
  { name: "img-src", chain: ["img-src", "default-src"], governs: "images, including tracking pixels" },
  { name: "font-src", chain: ["font-src", "default-src"], governs: "web fonts" },
  { name: "media-src", chain: ["media-src", "default-src"], governs: "audio and video" },
  { name: "frame-src", chain: ["frame-src", "child-src", "default-src"], governs: "iframes" },
  { name: "object-src", chain: ["object-src", "default-src"], governs: "<object> and <embed>" },
  { name: "manifest-src", chain: ["manifest-src", "default-src"], governs: "the web app manifest" },
  { name: "form-action", chain: ["form-action"], governs: "form submissions" },
  { name: "worker-src", chain: WORKER_SRC_CHAIN, governs: "static imports in module workers, in Chromium" },
];

export const WORKER_DIRECTIVES: CheckedDirective[] = [
  { name: "connect-src", chain: ["connect-src", "default-src"], governs: "fetch, XHR, WebSocket and EventSource" },
  { name: "script-src-elem", chain: ["script-src-elem", "script-src", "default-src"], governs: "importScripts and import()" },
  { name: "worker-src", chain: WORKER_SRC_CHAIN, governs: "static imports in module workers, in Firefox and Safari" },
  { name: "font-src", chain: ["font-src", "default-src"], governs: "web fonts" },
];

export function parsePolicy(text: string, source: PolicySource): Policy {
  const directives = new Map<string, string[]>();
  for (const part of text.split(";")) {
    const tokens = part.trim().split(/[\t\n\f\r ]+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0]!.toLowerCase();
    if (!/^[a-z0-9-]+$/.test(name) || directives.has(name)) continue;
    if (source === "meta" && META_IGNORED.has(name)) continue;
    directives.set(name, tokens.slice(1));
  }
  return { source, text: text.trim(), directives };
}

export function parsePolicyList(value: string, source: PolicySource): Policy[] {
  return value
    .split(",")
    .map((text) => parsePolicy(text, source))
    .filter((policy) => policy.directives.size > 0);
}

export function parseReportingEndpoints(value: string | null): Map<string, string> {
  const endpoints = new Map<string, string>();
  if (!value) return endpoints;
  for (const match of value.matchAll(/([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"/g)) {
    endpoints.set(match[1]!, match[2]!);
  }
  return endpoints;
}

export function normalizeAllowEntry(entry: string): string {
  const trimmed = entry.trim().toLowerCase();
  const withoutScheme = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  return withoutScheme.replace(/[/:].*$/, "");
}

function covers(pattern: string, host: string): boolean {
  if (pattern === host) return true;
  if (!pattern.startsWith("*.")) return false;
  const suffix = pattern.slice(1);
  return host.endsWith(suffix) && host.length > suffix.length;
}

function narrower(a: string, b: string): string | undefined {
  if (a === ANY_HOST) return b;
  if (b === ANY_HOST) return a;
  if (covers(a, b)) return b;
  if (covers(b, a)) return a;
  return undefined;
}

function hostOfSource(source: string): string | undefined {
  const match = /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?)(?::(?:\d+|\*))?(?:\/.*)?$/.exec(source);
  if (!match) return undefined;
  if (match[1] && !NETWORK_SCHEMES.has(match[1])) return undefined;
  return match[2]!.replace(/\.$/, "");
}

interface Reach {
  reaches: string;
  via: string;
}

function reachesOf(sources: string[], scriptLike: boolean, allowed: (host: string) => boolean): Reach[] {
  const out: Reach[] = [];
  for (const raw of sources) {
    const source = raw.toLowerCase();
    if (source.startsWith("'")) {
      if (source === "'strict-dynamic'" && scriptLike) out.push({ reaches: ANY_HOST, via: raw });
      continue;
    }
    if (source === "*") {
      out.push({ reaches: ANY_HOST, via: raw });
      continue;
    }
    const scheme = /^([a-z][a-z0-9+.-]*):$/.exec(source);
    if (scheme) {
      if (NETWORK_SCHEMES.has(scheme[1]!)) out.push({ reaches: ANY_HOST, via: raw });
      continue;
    }
    const host = hostOfSource(source);
    if (host === undefined) continue;
    if (host === "*") out.push({ reaches: ANY_HOST, via: raw });
    else if (!allowed(host)) out.push({ reaches: host, via: raw });
  }
  return out;
}

function directiveReaches(policy: Policy, chain: string[], allowed: (host: string) => boolean): Reach[] {
  for (const name of chain) {
    const sources = policy.directives.get(name);
    if (sources) return reachesOf(sources, SCRIPT_DIRECTIVES.has(name) && (chain[0] === "script-src-elem" || chain[0] === "worker-src"), allowed);
  }
  return [{ reaches: ANY_HOST, via: `no ${chain[0]} directive` }];
}

function intersect(perPolicy: Reach[][]): { reaches: string; via: string[] }[] {
  let current = perPolicy[0]!.map((reach) => ({ reaches: reach.reaches, via: [reach.via] }));
  for (const next of perPolicy.slice(1)) {
    const merged = new Map<string, string[]>();
    for (const a of current) {
      for (const b of next) {
        const host = narrower(a.reaches, b.reaches);
        if (host === undefined) continue;
        merged.set(host, [...new Set([...(merged.get(host) ?? []), ...a.via, b.via])]);
      }
    }
    current = [...merged].map(([reaches, via]) => ({ reaches, via }));
  }
  const any = current.find((reach) => reach.reaches === ANY_HOST);
  return any ? [any] : current;
}

export function hostAllowList(pageUrl: string, allow: string[] = []): (host: string) => boolean {
  const self = new URL(pageUrl).hostname.toLowerCase();
  const patterns = allow.map(normalizeAllowEntry).filter(Boolean);
  return (host) => {
    const lower = host.toLowerCase();
    if (lower === self) return true;
    return patterns.some((pattern) => covers(pattern, lower) || pattern === lower);
  };
}

export function evaluatePolicies(policies: Policy[], options: EvaluateOptions): Finding[] {
  const allowed = hostAllowList(options.pageUrl, options.allow);
  const findings: Finding[] = [];

  for (const directive of options.directives ?? CHECKED_DIRECTIVES) {
    if (policies.length === 0) {
      findings.push({ directive: directive.name, governs: directive.governs, reaches: ANY_HOST, via: ["no Content-Security-Policy"] });
      continue;
    }
    const perPolicy = policies.map((policy) => directiveReaches(policy, directive.chain, allowed));
    if (perPolicy.some((reaches) => reaches.length === 0)) continue;
    for (const reach of intersect(perPolicy)) {
      findings.push({ directive: directive.name, governs: directive.governs, ...reach });
    }
  }

  for (const policy of policies) {
    for (const uri of policy.directives.get("report-uri") ?? []) {
      findings.push(...reportFinding("report-uri", uri, uri, allowed));
    }
    const group = policy.directives.get("report-to")?.[0];
    const endpoint = group ? options.reportingEndpoints?.get(group) : undefined;
    if (group && endpoint) findings.push(...reportFinding("report-to", endpoint, `report-to ${group}`, allowed));
  }

  const merged = new Map<string, Finding>();
  for (const finding of findings) {
    const key = `${finding.directive} ${finding.reaches}`;
    const existing = merged.get(key);
    if (existing) existing.via = [...new Set([...existing.via, ...finding.via])];
    else merged.set(key, { ...finding, via: [...finding.via] });
  }
  return [...merged.values()];
}

function reportFinding(directive: string, url: string, via: string, allowed: (host: string) => boolean): Finding[] {
  let host: string;
  try {
    host = new URL(url, "https://invalid.invalid").hostname;
  } catch {
    return [];
  }
  if (host === "invalid.invalid" || allowed(host)) return [];
  return [{ directive, governs: "violation reports", reaches: host, via: [via] }];
}
