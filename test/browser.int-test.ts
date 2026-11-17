import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { BrowserUnavailableError, openRecorder } from "../src/index.js";
import { runCli } from "./run.js";
import { html, startServer, type TestServer } from "./server.js";

const unavailable = await openRecorder().then(
  (recorder) => recorder.close().then(() => undefined),
  (error: Error) => (error instanceof BrowserUnavailableError ? error.message : `Chromium failed to start: ${error.message}`),
);
if (unavailable && process.env.CI) throw new Error(`The browser tests must run in CI. ${unavailable}`);
if (unavailable) process.stderr.write(`\nSkipping the browser tests. ${unavailable}\n\n`);

const STRICT = "default-src 'self'; form-action 'self'";
const CORS = { "access-control-allow-origin": "*" };
const JS = { "content-type": "text/javascript" };

let page: TestServer;
let other: TestServer;
let elsewhere: string;

beforeAll(async () => {
  other = await startServer({
    "/data": { headers: { ...CORS, "content-type": "text/plain" }, body: "ok" },
    "/pixel.png": { headers: { "content-type": "image/png" }, body: "png" },
    "/font.woff2": { headers: { ...CORS, "content-type": "font/woff2" }, body: "font" },
    "/beacon": { headers: CORS, body: "" },
    "/events": { headers: { ...CORS, "content-type": "text/event-stream" }, body: "data: hello\n\n", stream: true },
    "/from-frame": { headers: CORS, body: "" },
    "/from-worker": { headers: CORS, body: "" },
    "/from-service-worker": { headers: CORS, body: "" },
  });
  elsewhere = `localhost:${other.port}`;
  const leaky = `<style>@font-face { font-family: f; src: url(http://${elsewhere}/font.woff2) } body { font-family: f }</style>`;
  const calls = (prefix: string) =>
    `fetch("http://${elsewhere}/${prefix}data").catch(() => {});
    navigator.sendBeacon("http://${elsewhere}/${prefix}beacon", "x");
    new WebSocket("ws://${elsewhere}/${prefix}socket");`;

  page = await startServer({
    "/leaky": {
      body: html(
        leaky,
        `<p>text</p><img src="http://${elsewhere}/pixel.png"><script>${calls("")} new EventSource("http://${elsewhere}/events");</script>`,
      ),
    },
    "/clean": {
      headers: { "content-security-policy": STRICT },
      body: html(`<script src="/clean.js"></script>`, `<img src="/pixel.png">`),
    },
    "/clean.js": { headers: JS, body: `fetch("/data");` },
    "/pixel.png": { headers: { "content-type": "image/png" }, body: "png" },
    "/data": { headers: { "content-type": "text/plain" }, body: "ok" },
    "/blocked": {
      headers: { "content-security-policy": "default-src 'self' 'unsafe-inline'; form-action 'self'" },
      body: html("", `<img src="http://${elsewhere}/blocked.png"><script>${calls("blocked-")}</script>`),
    },
    "/workers": {
      body: html(
        "",
        `<iframe src="/frame"></iframe><script>new Worker("/worker.js"); navigator.serviceWorker.register("/service-worker.js");</script><img src="/gate.png">`,
      ),
    },
    "/frame": { body: html("", `<script>fetch("http://${elsewhere}/from-frame");</script>`) },
    "/worker.js": { headers: JS, body: `fetch("http://${elsewhere}/from-worker");` },
    "/service-worker.js": {
      headers: JS,
      body: `self.addEventListener("install", (event) => event.waitUntil(fetch("http://${elsewhere}/from-service-worker")));`,
    },
    "/worker-policies": {
      headers: { "content-security-policy": "default-src 'self' 'unsafe-inline' blob:; form-action 'self'" },
      body: html(
        `<base href="/app/">`,
        `<script>
          new Worker("/strict-worker.js");
          new SharedWorker("shared-worker.js");
          new Worker(URL.createObjectURL(new Blob(["1"], { type: "text/javascript" })));
          navigator.serviceWorker.register("/open-service-worker.js");
        </script><img src="/worker-gate.png">`,
      ),
    },
    "/strict-worker.js": { headers: { ...JS, "content-security-policy": "default-src 'self'" }, body: "" },
    "/app/shared-worker.js": { headers: JS, body: "" },
    "/open-service-worker.js": { headers: JS, body: "" },
    "/worker-gate.png": {
      headers: { "content-type": "image/png" },
      before: () => Promise.all(["/strict-worker.js", "/app/shared-worker.js", "/open-service-worker.js"].map((path) => page.waitForHit(path))),
    },
    "/never-loads": { body: html("", `<img src="/hang">`) },
    "/hang": { hang: true },
    "/gate.png": {
      headers: { "content-type": "image/png" },
      before: () => Promise.all(["/from-frame", "/from-worker", "/from-service-worker"].map((path) => other.waitForHit(path))),
    },
  });
});

afterAll(async () => {
  await page?.close();
  await other?.close();
});

const browser = (...args: string[]) => runCli(["--browser", ...args]);

describe.skipIf(unavailable !== undefined)("--browser", () => {
  it("reports each request to another host, grouped by host with its types", async () => {
    const { code, out } = await browser(page.url("/leaky"));
    expect(code).toBe(1);
    expect(out).toContain(": FAIL: no Content-Security-Policy is enforced");
    expect(out).toContain(`/leaky: FAIL: in Chromium, the page contacted 1 other host\n  localhost: 6 requests (`);
    const json = JSON.parse((await browser("--json", page.url("/leaky"))).out);
    expect(json[0].browser.contacted).toEqual([
      { host: "localhost", requests: 6, failed: 0, types: { fetch: 1, beacon: 1, websocket: 1, image: 1, font: 1, eventsource: 1 } },
    ]);
    expect(other.hits("/beacon")).toBe(2);
    expect(other.hits("/socket")).toBe(2);
  });

  it("passes a page that only uses its own origin, and says how many requests it made", async () => {
    const { code, out } = await browser(page.url("/clean"));
    expect(code).toBe(0);
    expect(out).toContain(": PASS: the Content-Security-Policy keeps every request on 127.0.0.1");
    expect(out).toMatch(/\/clean: PASS: in Chromium, every request stayed on 127\.0\.0\.1:\d+ and the allowed hosts \(\d+ requests\)/);
  });

  it("lists requests the policy refused as blocked, not as contacted", async () => {
    const { code, out } = await browser(page.url("/blocked"));
    expect(code).toBe(0);
    expect(out).toContain("/blocked: PASS: in Chromium");
    expect(out).toContain("  blocked by the Content-Security-Policy, never sent: localhost: 4 requests (3 connect-src, 1 image)\n");
    for (const path of ["/blocked.png", "/blocked-data", "/blocked-beacon", "/blocked-socket"]) expect(other.hits(path)).toBe(0);
  });

  it("records requests from frames, workers and service workers", async () => {
    const json = JSON.parse((await browser("--json", page.url("/workers"))).out);
    const contacted = json[0].browser.requests.filter((r: { host: string }) => r.host === "localhost");
    expect(contacted.map((r: { url: string; from: string }) => `${new URL(r.url).pathname} ${r.from}`).sort()).toEqual([
      "/from-frame page",
      "/from-service-worker service worker",
      "/from-worker page",
    ]);
    expect(json[0].browser.contacted[0].types).toEqual({ fetch: 2, "fetch from a service worker": 1 });
  });

  it("checks the script of every worker the page starts against the worker's own policy", async () => {
    const { code, out } = await browser("--timeout", "4000", page.url("/worker-policies"));
    expect(code).toBe(1);
    expect(out).toContain("note: Chromium didn't report the network as idle within 4000 ms");
    expect(out).toContain("/worker-policies: PASS: the Content-Security-Policy keeps every request");
    expect(out).toContain(`${page.url("/strict-worker.js")} (worker): PASS: the worker's own Content-Security-Policy`);
    expect(out).toContain(`${page.url("/app/shared-worker.js")} (shared worker): FAIL: the script is served without a Content-Security-Policy, so the shared worker can contact any host`);
    expect(out).toContain(`${page.url("/open-service-worker.js")} (service worker): FAIL: the script is served without a Content-Security-Policy`);
    expect(out).not.toContain("blob:");

    const json = JSON.parse((await browser("--json", "--timeout", "4000", page.url("/worker-policies"))).out);
    const workers = json[0].workers.map((w: { url: string; kind: string; report: { ok: boolean } }) => `${new URL(w.url).pathname} ${w.kind} ${w.report.ok}`);
    expect(workers.sort()).toEqual(["/app/shared-worker.js shared worker false", "/open-service-worker.js service worker false", "/strict-worker.js worker true"]);
  });

  it("stops reporting a host once it is allowed", async () => {
    const allowed = JSON.parse((await browser("--json", "--allow", "localhost", page.url("/leaky"))).out);
    expect(allowed[0].browser).toMatchObject({ ok: true, contacted: [] });
    const subdomains = JSON.parse((await browser("--json", "-a", "*.localhost", page.url("/leaky"))).out);
    expect(subdomains[0].browser.ok).toBe(false);
  });

  it("fails when the policy fails, even if every recorded request stayed on allowed hosts", async () => {
    const { code, out } = await browser("--allow", "localhost", page.url("/leaky"));
    expect(out).toContain(": FAIL: no Content-Security-Policy is enforced");
    expect(out).toContain("/leaky: PASS: in Chromium");
    expect(code).toBe(1);
  });

  it("prints the policy report and the recording together with --json", async () => {
    const json = JSON.parse((await browser("--json", "--wait", "100", page.url("/blocked"))).out);
    expect(Object.keys(json[0]).sort()).toEqual(["browser", "report", "url"]);
    expect(json[0].report).toMatchObject({ ok: true, findings: [] });
    expect(Object.keys(json[0].browser).sort()).toEqual(["blocked", "contacted", "finalUrl", "notes", "ok", "requests", "status", "url", "workers"]);
    expect(json[0].browser).toMatchObject({ ok: true, status: 200, contacted: [], workers: [], notes: [] });
    expect(json[0].browser.requests.find((r: { url: string }) => r.url.endsWith("/blocked.png"))).toEqual({
      url: `http://${elsewhere}/blocked.png`,
      host: "localhost",
      type: "image",
      from: "page",
      blocked: "csp",
    });
  });

  it("exits 2 when the page does not finish loading in time", async () => {
    const { code, out } = await browser("--timeout", "1000", page.url("/never-loads"));
    expect(code).toBe(2);
    expect(out).toMatch(/\/never-loads: ERROR: timed out\n$/);
  });
});

describe("--browser without Chromium", () => {
  it("exits 2 and says how to install it", async () => {
    const empty = await mkdtemp(join(tmpdir(), "no-phone-home-"));
    try {
      const { code, out, err } = await runCli(["--browser", "http://127.0.0.1:9/"], { ...process.env, PLAYWRIGHT_BROWSERS_PATH: empty });
      expect(code).toBe(2);
      expect(out).toBe("");
      expect(err).toMatch(/needs Chromium for Playwright, which is not installed\. Install it with: npx playwright-core@\d+\.\d+\.\d+ install chromium/);
    } finally {
      await rm(empty, { recursive: true, force: true });
    }
  });
});
