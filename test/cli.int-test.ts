import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkWorker } from "../src/index.js";
import { runCli } from "./run.js";
import { startServer, type TestServer } from "./server.js";

const JS = { "content-type": "text/javascript" };

let server: TestServer;
let elsewhere: TestServer;

beforeAll(async () => {
  elsewhere = await startServer({ "/worker.js": { headers: { ...JS, "content-security-policy": "default-src 'self'" } } });
  server = await startServer({
    "/strict": { headers: { "content-security-policy": "default-src 'self'; form-action 'self'" } },
    "/api": { headers: { "content-security-policy": "default-src 'self'; form-action 'self'; connect-src 'self' api.example.com" } },
    "/many": {
      headers: {
        "content-security-policy":
          "default-src 'self'; form-action 'self'; connect-src 'self' a.example.com wss://a.example.com b.example.com c.example.com d.example.com e.example.com f.example.com",
      },
    },
    "/none": {},
    "/hang": { hang: true },
    "/open-worker.js": { headers: JS },
    "/strict-worker.js": { headers: { ...JS, "content-security-policy": "default-src 'self'" } },
    "/moved-worker.js": { status: 302, headers: { location: `http://localhost:${elsewhere.port}/worker.js` }, body: "" },
    "/module-imports": { headers: { "content-security-policy": "default-src 'self'; form-action 'self'; worker-src 'self' modules.example.com" } },
    "/module-worker.js": { headers: { ...JS, "content-security-policy": "default-src 'self'; worker-src 'self' modules.example.com" } },
    "/text-worker.js": { headers: { "content-type": "text/plain", "content-security-policy": "default-src 'self'" } },
    "/api-worker.js": { headers: { ...JS, "content-security-policy": "default-src 'self'; connect-src 'self' api.example.com; report-uri https://reports.example.com/csp" } },
  });
});

afterAll(() => Promise.all([server.close(), elsewhere.close()]));

const run = (...args: string[]) => runCli(args);

describe("no-phone-home command", () => {
  it("exits 0 and prints PASS for a locked-down page", async () => {
    const { code, out } = await run(server.url("/strict"));
    expect(code).toBe(0);
    expect(out).toMatch(/PASS/);
  });

  it("exits 1 and names the host and the directive", async () => {
    const { code, out } = await run(server.url("/api"));
    expect(code).toBe(1);
    expect(out).toContain("connect-src (fetch, XHR, WebSocket, EventSource and sendBeacon): api.example.com\n");
  });

  it("lists each host once per directive and shortens long lists", async () => {
    const { out } = await run(server.url("/many"));
    expect(out).toContain("connect-src (fetch, XHR, WebSocket, EventSource and sendBeacon): a.example.com, b.example.com, c.example.com, d.example.com and 2 more\n");
    const json = JSON.parse((await run("--json", server.url("/many"))).out);
    expect(json[0].report.findings[0]).toMatchObject({ reaches: "a.example.com", via: ["a.example.com", "wss://a.example.com"] });
    expect(json[0].report.findings).toHaveLength(6);
  });

  it("prints one line for a page with no policy", async () => {
    const { code, out } = await run(server.url("/none"));
    expect(code).toBe(1);
    expect(out.trim().split("\n")).toHaveLength(1);
    expect(out).toMatch(/no Content-Security-Policy is enforced/);
  });

  it("passes once the host is allowed, with --allow or -a", async () => {
    expect((await run("--allow", "api.example.com", server.url("/api"))).code).toBe(0);
    expect((await run("-a", "api.example.com", server.url("/api"), server.url("/strict"))).code).toBe(0);
  });

  it("fails the run if any one of several pages fails", async () => {
    expect((await run(server.url("/strict"), server.url("/api"))).code).toBe(1);
  });

  it("prints JSON reports with --json and nothing with --quiet", async () => {
    const json = JSON.parse((await run("--json", server.url("/api"))).out);
    expect(json[0].report.findings[0]).toMatchObject({ directive: "connect-src", reaches: "api.example.com" });
    expect(json[0]).not.toHaveProperty("browser");
    const quiet = await run("-q", server.url("/api"));
    expect(quiet).toMatchObject({ code: 1, out: "" });
  });

  it("exits 2 for an unreachable page, a non-URL or a bad option", async () => {
    const unreachable = await run("http://127.0.0.1:9/");
    expect(unreachable.code).toBe(2);
    expect(unreachable.out).toMatch(/ERROR: fetch failed: .+/);
    const slow = await run("--timeout", "300", server.url("/hang"));
    expect(slow).toMatchObject({ code: 2 });
    expect(slow.out).toMatch(/ERROR: timed out/);
    expect((await run("./index.html")).code).toBe(2);
    expect((await run("--timeout", "soon", server.url("/strict"))).code).toBe(2);
    expect((await run("--timeout", "0x10", server.url("/strict"))).code).toBe(2);
    expect((await run("--timeout", "3000000000", server.url("/strict"))).code).toBe(2);
    expect((await run("--nope")).code).toBe(2);
    expect((await run("--wait", "500", server.url("/strict"))).err).toMatch(/--wait only applies with --browser/);
    expect((await run("--browser", "--wait", "soon", server.url("/strict"))).err).toMatch(/--wait must be a non-negative whole number/);
    expect((await run()).code).toBe(2);
  });

  it("checks a worker script against its own policy, not the page's", async () => {
    const open = await run("--worker", "/open-worker.js", server.url("/strict"));
    expect(open.code).toBe(1);
    expect(open.out).toContain("/strict: PASS");
    expect(open.out).toContain(`${server.url("/open-worker.js")} (worker): FAIL: the script is served without a Content-Security-Policy, so the worker can contact any host\n`);

    const strict = await run("-w", "strict-worker.js", server.url("/strict"));
    expect(strict.code).toBe(0);
    expect(strict.out).toContain(`${server.url("/strict-worker.js")} (worker): PASS: the worker's own Content-Security-Policy keeps its requests on 127.0.0.1`);
  });

  it("checks only what a worker can request, and its violation reports", async () => {
    const { code, out } = await run("--worker", "/api-worker.js", server.url("/strict"));
    expect(code).toBe(1);
    expect(out).toContain(
      "(worker): FAIL: the worker can contact hosts outside the allowlist\n" +
        "  connect-src (fetch, XHR, WebSocket and EventSource): api.example.com\n" +
        "  report-uri (violation reports): reports.example.com\n",
    );
    expect((await run("-a", "api.example.com", "-a", "reports.example.com", "-w", "/api-worker.js", server.url("/strict"))).code).toBe(0);
    const json = JSON.parse((await run("--json", "-w", "/api-worker.js", server.url("/strict"))).out);
    expect(json[0].workers).toEqual([
      {
        url: server.url("/api-worker.js"),
        kind: "worker",
        report: expect.objectContaining({ ok: false, status: 200, findings: [expect.objectContaining({ directive: "connect-src", reaches: "api.example.com" }), expect.anything()] }),
      },
    ]);
  });

  it("exits 2 when a worker script is missing", async () => {
    const { code, out } = await run("--worker", "/gone.js", server.url("/strict"));
    expect(code).toBe(2);
    expect(out).toContain(`${server.url("/gone.js")} (worker): ERROR: the server answered HTTP 404\n`);
  });

  it("checks static imports in module workers against worker-src, on the page and in the worker", async () => {
    const page = await run("--json", server.url("/module-imports"));
    expect(JSON.parse(page.out)[0].report.findings).toEqual([expect.objectContaining({ directive: "worker-src", reaches: "modules.example.com" })]);
    const worker = await run("--json", "-w", "/module-worker.js", server.url("/strict"));
    expect(JSON.parse(worker.out)[0].workers[0].report.findings).toEqual([expect.objectContaining({ directive: "worker-src", reaches: "modules.example.com" })]);
  });

  it("refuses an HTML page and odd --worker values instead of passing them", async () => {
    const html = await run("--worker", "/strict", server.url("/strict"));
    expect(html.code).toBe(2);
    expect(html.out).toContain(`${server.url("/strict")} (worker): ERROR: the server answered with a "text/html" page, not a script\n`);
    for (const value of ["", "data:text/javascript,1", "http://["]) {
      const bad = await run("--worker", value, server.url("/strict"));
      expect(bad.code).toBe(2);
      expect(bad.err).toContain(`--worker must be a path or an http:// or https:// URL, got "${value}"`);
    }
    const twice = JSON.parse((await run("--json", "-w", "/strict-worker.js", "-w", "/strict-worker.js#x", server.url("/strict"))).out);
    expect(twice[0].workers).toHaveLength(1);
  });

  it("refuses worker scripts that browsers would refuse to run", async () => {
    const moved = await run("--worker", "/moved-worker.js", server.url("/strict"));
    expect(moved.code).toBe(2);
    expect(moved.out).toContain(`(worker): ERROR: the script redirects to http://localhost:${elsewhere.port}, and browsers don't run a worker from another origin\n`);
    expect(elsewhere.hits("/worker.js")).toBe(1);
    await expect(checkWorker(server.url("/text-worker.js"), "service worker")).rejects.toThrow(
      'a service worker script must be served as JavaScript, and this one is served as "text/plain"',
    );
    expect((await checkWorker(server.url("/text-worker.js"), "worker")).ok).toBe(true);
  });

  it("prints its version", async () => {
    expect((await run("--version")).out.trim()).toBe("0.1.0");
  });
});
