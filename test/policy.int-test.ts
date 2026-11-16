import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ANY_HOST, checkUrl, type PageReport } from "../src/index.js";
import { html, startServer, type TestServer } from "./server.js";

const STRICT = "default-src 'self'; form-action 'self'";

let server: TestServer;

beforeAll(async () => {
  server = await startServer({
    "/none": {},
    "/strict": { headers: { "content-security-policy": STRICT } },
    "/no-form-action": { headers: { "content-security-policy": "default-src 'self'" } },
    "/https-scheme": { headers: { "content-security-policy": `${STRICT}; connect-src 'self' https:` } },
    "/star": { headers: { "content-security-policy": `${STRICT}; img-src *` } },
    "/named-host": { headers: { "content-security-policy": `${STRICT}; connect-src 'self' https://api.example.com/v1/` } },
    "/wildcard-host": { headers: { "content-security-policy": `${STRICT}; font-src *.fonts.example.net` } },
    "/fallback-chain": { headers: { "content-security-policy": `${STRICT}; script-src 'self' cdn.example.org` } },
    "/child-src": { headers: { "content-security-policy": `${STRICT}; child-src blob: frames.example.org` } },
    "/strict-dynamic": {
      headers: { "content-security-policy": `${STRICT}; script-src 'nonce-abc' 'strict-dynamic' 'self'` },
    },
    "/two-policies": {
      headers: { "content-security-policy": "default-src 'self' https:; form-action 'self', default-src 'self'; form-action 'self'" },
    },
    "/two-policies-overlap": {
      headers: {
        "content-security-policy": `${STRICT}; connect-src 'self' https:, ${STRICT}; connect-src 'self' *.example.com other.example.org`,
      },
    },
    "/report-uri": { headers: { "content-security-policy": `${STRICT}; report-uri https://reports.example.io/csp` } },
    "/report-uri-relative": { headers: { "content-security-policy": `${STRICT}; report-uri /csp-reports` } },
    "/report-to": {
      headers: {
        "content-security-policy": `${STRICT}; report-to main`,
        "reporting-endpoints": 'main="https://collect.example.io/r"',
      },
    },
    "/report-only": { headers: { "content-security-policy-report-only": STRICT } },
    "/meta": { body: html(`<meta http-equiv="Content-Security-Policy" content="${STRICT}">`) },
    "/meta-entities": {
      body: html(`<meta http-equiv="content-security-policy" content="default-src &#39;self&#39;; form-action &apos;self&apos;">`),
    },
    "/meta-late": {
      body: html(`<script src="https://cdn.example.org/a.js"></script><meta http-equiv="Content-Security-Policy" content="${STRICT}">`),
    },
    "/meta-after-canonical": {
      body: html(`<link rel="canonical" href="https://example.org/"><meta http-equiv="Content-Security-Policy" content="${STRICT}">`),
    },
    "/meta-in-body": {
      body: html("", `<p>x</p><meta http-equiv="Content-Security-Policy" content="${STRICT}">`),
    },
    "/meta-report-uri": {
      body: html(`<meta http-equiv="Content-Security-Policy" content="${STRICT}; report-uri https://reports.example.io/csp">`),
    },
    "/header-and-meta": {
      headers: { "content-security-policy": "default-src *; form-action *" },
      body: html(`<meta http-equiv="Content-Security-Policy" content="${STRICT}">`),
    },
    "/redirect": { status: 302, headers: { location: "/strict", "content-security-policy": "default-src *" } },
    "/missing-page": { status: 404, headers: { "content-security-policy": STRICT } },
    "/not-html": {
      headers: { "content-type": "application/json", "content-security-policy": STRICT },
      body: '{"meta":"<meta http-equiv=content-security-policy content=x>"}',
    },
  });
});

afterAll(() => server.close());

const check = (path: string, allow: string[] = []) => checkUrl(server.url(path), { allow });

function reaches(report: PageReport): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const finding of report.findings) (out[finding.directive] ??= []).push(finding.reaches);
  return out;
}

describe("pages that cannot contact other hosts", () => {
  it("passes default-src 'self' with form-action 'self'", async () => {
    const report = await check("/strict");
    expect(report.ok).toBe(true);
    expect(report.findings).toEqual([]);
  });

  it("reads a policy from a <meta> tag, decoding entities", async () => {
    expect((await check("/meta")).ok).toBe(true);
    expect((await check("/meta-entities")).ok).toBe(true);
  });

  it("enforces every policy: a strict second policy closes what the first one opens", async () => {
    const report = await check("/two-policies");
    expect(report.policies).toHaveLength(2);
    expect(report.ok).toBe(true);
  });

  it("combines header and meta policies the same way", async () => {
    expect((await check("/header-and-meta")).ok).toBe(true);
  });

  it("ignores a same-origin report-uri", async () => {
    expect((await check("/report-uri-relative")).ok).toBe(true);
  });

  it("uses the policy of the page a redirect ends on", async () => {
    const report = await check("/redirect");
    expect(report.finalUrl).toBe(server.url("/strict"));
    expect(report.ok).toBe(true);
  });
});

describe("pages that can contact other hosts", () => {
  it("fails every directive when there is no policy at all", async () => {
    const report = await check("/none");
    expect(report.ok).toBe(false);
    expect(Object.keys(reaches(report))).toContain("connect-src");
    expect(report.findings.every((f) => f.reaches === ANY_HOST)).toBe(true);
  });

  it("flags a missing form-action, which default-src does not cover", async () => {
    expect(reaches(await check("/no-form-action"))).toEqual({ "form-action": [ANY_HOST] });
  });

  it("treats a bare https: scheme as any host", async () => {
    const report = await check("/https-scheme");
    expect(reaches(report)).toEqual({ "connect-src": [ANY_HOST] });
    expect(report.findings[0]!.via).toEqual(["https:"]);
  });

  it("treats * as any host", async () => {
    expect(reaches(await check("/star"))).toEqual({ "img-src": [ANY_HOST] });
  });

  it("names a listed host until it is allowed", async () => {
    expect(reaches(await check("/named-host"))).toEqual({ "connect-src": ["api.example.com"] });
    expect((await check("/named-host", ["api.example.com"])).ok).toBe(true);
    expect((await check("/named-host", ["https://api.example.com"])).ok).toBe(true);
  });

  it("matches wildcard hosts only against a wildcard allow entry", async () => {
    expect(reaches(await check("/wildcard-host", ["fonts.example.net"]))).toEqual({ "font-src": ["*.fonts.example.net"] });
    expect((await check("/wildcard-host", ["*.fonts.example.net"])).ok).toBe(true);
    expect((await check("/wildcard-host", ["*.example.net"])).ok).toBe(true);
  });

  it("follows the fallback chain: script-src covers script elements", async () => {
    expect(reaches(await check("/fallback-chain"))).toEqual({ "script-src-elem": ["cdn.example.org"] });
  });

  it("follows frame-src to child-src", async () => {
    expect(reaches(await check("/child-src"))).toEqual({ "frame-src": ["frames.example.org"] });
  });

  it("treats 'strict-dynamic' as letting scripts load from any host", async () => {
    const report = await check("/strict-dynamic");
    expect(reaches(report)["script-src-elem"]).toEqual([ANY_HOST]);
    expect(report.findings.find((f) => f.directive === "script-src-elem")!.via).toEqual(["'strict-dynamic'"]);
  });

  it("reports only the hosts every policy allows", async () => {
    expect(reaches(await check("/two-policies-overlap"))).toEqual({
      "connect-src": ["*.example.com", "other.example.org"],
    });
  });

  it("flags violation reports sent to another host", async () => {
    expect(reaches(await check("/report-uri"))).toEqual({ "report-uri": ["reports.example.io"] });
    expect(reaches(await check("/report-to"))).toEqual({ "report-to": ["collect.example.io"] });
    expect((await check("/report-to", ["collect.example.io"])).ok).toBe(true);
  });

  it("does not enforce a report-only policy", async () => {
    const report = await check("/report-only");
    expect(report.ok).toBe(false);
    expect(report.reportOnly).toEqual([STRICT]);
  });

  it("ignores report-uri inside a <meta> policy, as browsers do", async () => {
    expect((await check("/meta-report-uri")).ok).toBe(true);
  });

  it("ignores a <meta> policy outside <head> and says so", async () => {
    const report = await check("/meta-in-body");
    expect(report.ok).toBe(false);
    expect(report.warnings[0]).toMatch(/outside <head>/);
  });

  it("warns when a <meta> policy comes after something that loads", async () => {
    const report = await check("/meta-late");
    expect(report.ok).toBe(true);
    expect(report.warnings[0]).toMatch(/after <script src="https:\/\/cdn\.example\.org\/a\.js">/);
    expect((await check("/meta-after-canonical")).warnings).toEqual([]);
  });

  it("still checks the headers of an error page or a non-HTML response", async () => {
    expect((await check("/missing-page")).status).toBe(404);
    expect((await check("/missing-page")).ok).toBe(true);
    const json = await check("/not-html");
    expect(json.ok).toBe(true);
    expect(json.policies).toHaveLength(1);
  });
});
