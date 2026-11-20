import { createServer, validateHeaderName, validateHeaderValue } from "node:http";
import type { AddressInfo } from "node:net";
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, extname, join, resolve, sep } from "node:path";
import { pathToRegexp, type Key } from "path-to-regexp";

export interface ServeOptions {
  headers?: string;
  host?: HeadersFileHost;
}

export interface ServedSite {
  url: string;
  pages: string[];
  config: string | null;
  notes: string[];
  close(): Promise<void>;
}

type HeaderList = [string, string][];

interface HeaderConfig {
  headersFor(pathname: string): HeaderList;
  style: UrlStyle;
  alternates?(file: string, page: string): string[];
  notes: string[];
}

export type HeadersFileHost = "cloudflare" | "netlify";

interface UrlStyle {
  stripHtml: boolean;
  dirSlash: boolean;
  fileSlash: boolean;
}

const CLOUDFLARE_STYLE: UrlStyle = { stripHtml: true, dirSlash: true, fileSlash: false };

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".map": "application/json",
  ".webmanifest": "application/manifest+json",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml",
  ".wasm": "application/wasm",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".otf": "font/otf",
  ".pdf": "application/pdf",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
};

function headerProblem(name: string, value: string): string | undefined {
  try {
    validateHeaderName(name);
    validateHeaderValue(name, value);
    return undefined;
  } catch {
    return `"${name}: ${value.length > 40 ? `${value.slice(0, 40)}...` : value}" is not a valid HTTP header`;
  }
}

function substitute(value: string, names: (string | number)[], match: RegExpExecArray): string {
  return value.replace(/:([A-Za-z_]\w*)/g, (text, name: string) => {
    const index = names.indexOf(name);
    return index === -1 ? text : (match[index + 1] ?? "");
  });
}

function vercelConfig(text: string, file: string): HeaderConfig {
  let config: unknown;
  try {
    config = JSON.parse(text);
  } catch (error) {
    throw new Error(`${file} is not valid JSON: ${(error as Error).message}`);
  }
  if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error(`${file} must contain a JSON object`);
  const { headers = [], cleanUrls = false, trailingSlash, routes } = config as { headers?: unknown; cleanUrls?: unknown; trailingSlash?: unknown; routes?: unknown };
  if (!Array.isArray(headers)) throw new Error(`${file}: "headers" must be an array`);
  if (typeof cleanUrls !== "boolean") throw new Error(`${file}: "cleanUrls" must be true or false`);
  if (trailingSlash !== undefined && typeof trailingSlash !== "boolean") throw new Error(`${file}: "trailingSlash" must be true or false`);

  const notes: string[] = routes === undefined ? [] : [`${file}: "routes" is not read, so headers it sets are not applied`];
  const rules: { regex: RegExp; names: (string | number)[]; headers: HeaderList }[] = [];
  headers.forEach((rule: unknown, i: number) => {
    const where = `${file}: headers[${i}]`;
    const { source, headers: list, has, missing } = (rule ?? {}) as { source?: unknown; headers?: unknown; has?: unknown; missing?: unknown };
    if (typeof source !== "string" || !source.startsWith("/")) throw new Error(`${where}.source must be a path starting with "/"`);
    if (!Array.isArray(list) || list.some((h) => typeof h?.key !== "string" || typeof h?.value !== "string")) {
      throw new Error(`${where}.headers must be a list of { "key": ..., "value": ... }`);
    }
    if (has !== undefined || missing !== undefined) {
      notes.push(`${where} (${source}) has a "has" or "missing" condition, which can't be judged locally, so its headers are not applied`);
      return;
    }
    const keys: Key[] = [];
    let regex: RegExp;
    try {
      regex = pathToRegexp(source, keys, { strict: true, sensitive: true, delimiter: "/" });
    } catch (error) {
      throw new Error(`${where}.source "${source}" is not a valid pattern: ${(error as Error).message}`);
    }
    const valid = list.filter((h: { key: string; value: string }) => {
      const problem = h.key.includes(":") ? undefined : headerProblem(h.key, h.value);
      if (problem) notes.push(`${where}: ${problem}, so it is not applied`);
      return !problem;
    });
    rules.push({ regex, names: keys.map((k) => k.name), headers: valid.map((h: { key: string; value: string }) => [h.key, h.value]) });
  });

  return {
    notes,
    style: { stripHtml: cleanUrls, dirSlash: trailingSlash ?? !cleanUrls, fileSlash: cleanUrls && trailingSlash === true },
    alternates(file, page) {
      const forms: string[] = [];
      if (trailingSlash === undefined && page !== "/" && !page.endsWith(".html")) forms.push(page.endsWith("/") ? page.slice(0, -1) : `${page}/`);
      if (!cleanUrls && (file === "index.html" || file.endsWith("/index.html"))) forms.push(`/${file.split("/").map(encodeURIComponent).join("/")}`);
      return forms;
    },
    headersFor(pathname) {
      const out = new Map<string, [string, string]>();
      for (const rule of rules) {
        const match = rule.regex.exec(pathname);
        if (!match) continue;
        for (const [rawKey, value] of rule.headers) {
          const key = substitute(rawKey, rule.names, match);
          out.set(key.toLowerCase(), [key, substitute(value, rule.names, match)]);
        }
      }
      return [...out.values()];
    },
  };
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const POLICY_HEADERS = new Set(["content-security-policy", "content-security-policy-report-only", "reporting-endpoints"]);

const MAX_RULES = 100;
const MAX_LINE_LENGTH = 2000;

function headersFilePattern(pattern: string): { regex: RegExp; names: string[] } | string {
  const names: string[] = [];
  let source = "";
  for (const token of pattern.match(/\*|:[A-Za-z]\w*|[^*:]+|:/g) ?? []) {
    if (token === "*") {
      if (names.includes("splat")) return 'it has more than one "*"';
      names.push("splat");
      source += "(.*)";
    } else if (/^:[A-Za-z]/.test(token)) {
      if (names.includes(token.slice(1))) return `it uses the placeholder "${token}" twice`;
      names.push(token.slice(1));
      source += "([^/]+)";
    } else {
      source += escapeRegex(token);
    }
  }
  return { regex: new RegExp(`^${source}$`), names };
}

interface HeadersFileRule {
  path: string;
  set: Map<string, string>;
  unset: string[];
}

function headersFileConfig(text: string, file: string): HeaderConfig {
  const notes: string[] = [];
  const parsed: HeadersFileRule[] = [];
  let current: HeadersFileRule | undefined;
  for (const [i, raw] of text.split("\n").entries()) {
    const where = `${file} line ${i + 1}`;
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.length > MAX_LINE_LENGTH) {
      notes.push(`${where} is longer than ${MAX_LINE_LENGTH} characters, so Cloudflare ignores it, and so does this check`);
      continue;
    }
    if (/^([^\s]+:\/\/|\/)/.test(line)) {
      if (parsed.slice(0, -1).filter((rule) => rule.set.size || rule.unset.length).length >= MAX_RULES) {
        notes.push(`${where}: Cloudflare stops reading after ${MAX_RULES + 1} rules (its docs say ${MAX_RULES}), so this rule and the rest of the file are ignored`);
        break;
      }
      current = { path: line, set: new Map(), unset: [] };
      parsed.push(current);
      continue;
    }
    if (!current) {
      notes.push(`${where}: "${line}" comes before any path, so it is ignored`);
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) {
      if (line.startsWith("! ")) current.unset.push(line.slice(2).trim().toLowerCase());
      else notes.push(`${where}: expected "Name: value" or "! Name", got "${line}", so it is ignored`);
      continue;
    }
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!name || name.includes(" ") || !value) {
      notes.push(`${where}: "${line}" is not a valid "Name: value" line, so it is ignored`);
      continue;
    }
    const problem = headerProblem(name, value);
    if (problem) {
      notes.push(`${where}: ${problem}, so it is ignored`);
      continue;
    }
    const existing = current.set.get(name);
    current.set.set(name, existing ? `${existing}, ${value}` : value);
  }

  const byPath = new Map<string, HeadersFileRule>();
  for (const rule of parsed) if (rule.set.size || rule.unset.length) byPath.set(rule.path, rule);
  const rules: { regex: RegExp; names: string[]; rule: HeadersFileRule }[] = [];
  for (const rule of byPath.values()) {
    if (!rule.path.startsWith("/")) {
      notes.push(`${file}: the rule for "${rule.path}" names a host, which can't be matched locally, so its headers are not applied`);
      continue;
    }
    const pattern = headersFilePattern(rule.path);
    if (typeof pattern === "string") {
      notes.push(`${file}: the rule for "${rule.path}" is ignored, because ${pattern}`);
      continue;
    }
    rules.push({ ...pattern, rule });
  }

  return {
    notes,
    style: CLOUDFLARE_STYLE,
    headersFor(pathname) {
      const out = new Map<string, [string, string]>();
      const setByRule = new Set<string>();
      for (const { regex, names, rule } of rules) {
        const match = regex.exec(pathname);
        if (!match) continue;
        for (const name of rule.unset) out.delete(name);
        for (const [name, raw] of rule.set) {
          const value = substitute(raw, names, match);
          const existing = setByRule.has(name) ? out.get(name) : undefined;
          out.set(name, [name, existing ? `${existing[1]}, ${value}` : value]);
          setByRule.add(name);
        }
      }
      return [...out.values()];
    },
  };
}

function netlifyPattern(path: string): RegExp {
  const parts = path
    .split("/")
    .map((part) => part.trimEnd())
    .filter(Boolean)
    .map((part) => {
      if (part.startsWith(":")) return "([^/]+)";
      if (part === "*") return "?(.*)";
      if (part.includes("*")) return part.replaceAll("*", "(.*)");
      return escapeRegex(part);
    });
  return new RegExp(`^/${parts.join("/")}/?$`, "iu");
}

function netlifyHeadersConfig(text: string, file: string): HeaderConfig {
  const notes: string[] = [];
  const rules: { regex: RegExp | undefined; values: Map<string, string> }[] = [];
  for (const [i, raw] of text.split("\n").entries()) {
    const where = `${file} line ${i + 1}`;
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("/")) {
      let regex: RegExp | undefined;
      try {
        regex = netlifyPattern(line);
      } catch {
        notes.push(`${where}: "${line}" is not a pattern Netlify can match, so the rule is ignored`);
      }
      rules.push({ regex, values: new Map() });
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) {
      notes.push(`${where}: "${line}" has no colon, so Netlify ignores it${line.startsWith("!") ? " (Netlify has no \"!\" to remove a header)" : ""}`);
      continue;
    }
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    const rule = rules.at(-1);
    if (!name || !value || !rule) {
      notes.push(`${where}: "${line}" is ${rule ? "missing a header name or value" : "before any path"}, so Netlify ignores it`);
      continue;
    }
    const problem = headerProblem(name, value);
    if (problem) {
      notes.push(`${where}: ${problem}, so it is ignored`);
      continue;
    }
    const existing = rule.values.get(name);
    rule.values.set(name, existing === undefined ? value : `${existing}, ${value}`);
  }
  for (const rule of rules) {
    if (rule.values.has("undefined")) {
      notes.push(`${file}: a rule sets a header named "undefined", so Netlify drops the whole rule`);
      rule.regex = undefined;
    }
    for (const [name, value] of rule.values) rule.values.set(name, value.split(/\s*,\s*/g).join(", "));
  }
  return {
    notes,
    style: CLOUDFLARE_STYLE,
    headersFor(pathname) {
      const merged = new Map<string, string>();
      for (const { regex, values } of rules) if (regex?.test(pathname)) for (const [name, value] of values) merged.set(name, value);
      const out = new Map<string, [string, string]>();
      for (const [name, value] of merged) out.set(name.toLowerCase(), [name, value]);
      return [...out.values()];
    },
  };
}

async function isFile(path: string): Promise<boolean> {
  return (await stat(path).catch(() => undefined))?.isFile() ?? false;
}

async function loadConfig(dir: string, file: string | undefined, host: HeadersFileHost | undefined): Promise<{ config: HeaderConfig | null; path: string | null }> {
  const path = file ?? join(dir, "_headers");
  if (!file && !(await isFile(path))) return { config: null, path: null };
  const name = basename(path);
  if (name === "netlify.toml") throw new Error(`netlify.toml is not read; put the headers in a _headers file instead`);
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new Error(`can't read ${path}: ${(error as NodeJS.ErrnoException).code ?? (error as Error).message}`);
  }
  if (extname(name) === ".json") {
    if (host) throw new Error(`--host applies to a _headers file, not to ${name}`);
    return { config: vercelConfig(text, name), path };
  }
  return { config: host === "netlify" ? netlifyHeadersConfig(text, name) : headersFileConfig(text, name), path };
}

async function htmlFiles(dir: string, prefix = ""): Promise<string[]> {
  const found: string[] = [];
  for (const entry of await readdir(join(dir, prefix), { withFileTypes: true })) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...(await htmlFiles(dir, rel)));
    else if (entry.isFile() && entry.name.endsWith(".html")) found.push(rel);
  }
  return found;
}

function pagePath(file: string, style: UrlStyle): string {
  if (file === "index.html") return "/";
  if (file.endsWith("/index.html")) {
    const dir = `/${file.slice(0, -"/index.html".length)}`;
    return style.dirSlash ? `${dir}/` : dir;
  }
  if (!style.stripHtml) return `/${file}`;
  const page = `/${file.slice(0, -".html".length)}`;
  return style.fileSlash ? `${page}/` : page;
}

async function locate(root: string, pathname: string): Promise<string | undefined> {
  const base = resolve(root, `.${pathname}`);
  if (base !== root && !base.startsWith(root + sep)) return undefined;
  const candidates = pathname.endsWith("/") ? [join(base, "index.html"), `${base}.html`] : [base, `${base}.html`, join(base, "index.html")];
  for (const candidate of candidates) if (await isFile(candidate)) return candidate;
  return undefined;
}

export async function serveDirectory(dir: string, options: ServeOptions = {}): Promise<ServedSite> {
  const root = resolve(dir);
  if (!(await stat(root).catch(() => undefined))?.isDirectory()) throw new Error(`${dir} is not a folder`);
  const { config, path } = await loadConfig(dir, options.headers, options.host);
  if (options.host && !config) throw new Error(`--host ${options.host} needs a _headers file, and ${dir} has none`);
  const style = config?.style ?? CLOUDFLARE_STYLE;
  const notes = config
    ? [...config.notes]
    : ["no _headers file in the folder and no --headers file, so only <meta> policies are checked"];
  const byPage = new Map<string, string[]>();
  for (const file of (await htmlFiles(root)).sort()) {
    const page = pagePath(file, style).split("/").map(encodeURIComponent).join("/");
    byPage.set(page, [...(byPage.get(page) ?? []), file]);
  }
  for (const [page, files] of byPage) {
    if (files.length < 2) continue;
    const served = await locate(root, decodeURIComponent(page));
    const checked = files.find((file) => served === join(root, file)) ?? files[0]!;
    const skipped = files.filter((file) => file !== checked).join(" and ");
    notes.push(`${checked} and ${skipped} would both be served at ${page}; only ${checked} is checked there`);
  }
  const pages = [...byPage.keys()];
  const policyHeaders = (path: string) =>
    JSON.stringify(
      (config?.headersFor(path) ?? [])
        .map(([name, value]) => [name.toLowerCase(), value])
        .filter(([name]) => POLICY_HEADERS.has(name!))
        .sort(),
    );
  for (const [page, files] of byPage) {
    for (const other of config?.alternates?.(files[0]!, page) ?? []) {
      if (pages.includes(other) || policyHeaders(other) === policyHeaders(page)) continue;
      pages.push(other);
      notes.push(`${page} is also served at ${other}, with different policy headers, so both are checked`);
    }
  }
  pages.sort((a, b) => (a === "/" ? -1 : b === "/" ? 1 : a.localeCompare(b)));
  const notFound = join(root, "404.html");

  const server = createServer(async (request, response) => {
    try {
      const rawPath = new URL(request.url ?? "/", "http://localhost").pathname;
      let pathname: string;
      try {
        pathname = decodeURIComponent(rawPath);
      } catch {
        response.writeHead(400).end();
        return;
      }
      const found = pathname === "/_headers" ? undefined : await locate(root, pathname);
      const file = found ?? ((await isFile(notFound)) ? notFound : undefined);
      response.statusCode = found ? 200 : 404;
      for (const [name, value] of config?.headersFor(rawPath) ?? []) if (!headerProblem(name, value)) response.setHeader(name, value);
      response.setHeader("content-type", file ? (CONTENT_TYPES[extname(file).toLowerCase()] ?? "application/octet-stream") : "text/plain; charset=utf-8");
      response.end(request.method === "HEAD" ? undefined : file ? await readFile(file) : "Not found");
    } catch {
      if (!response.headersSent) response.writeHead(500);
      response.end();
    }
  });
  await new Promise<void>((done, fail) => {
    server.once("error", fail);
    server.listen(0, "127.0.0.1", done);
  });
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    pages,
    config: path,
    notes,
    close: () =>
      new Promise<void>((done) => {
        server.closeAllConnections();
        server.close(() => done());
      }),
  };
}
