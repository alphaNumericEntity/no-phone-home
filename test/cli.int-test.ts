import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runCli } from "./run.js";
import { startServer, type TestServer } from "./server.js";

let server: TestServer;

beforeAll(async () => {
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
  });
});

afterAll(() => server.close());

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
    expect((await run("--nope")).code).toBe(2);
    expect((await run("--wait", "500", server.url("/strict"))).err).toMatch(/--wait only applies with --browser/);
    expect((await run("--browser", "--wait", "soon", server.url("/strict"))).err).toMatch(/--wait must be a non-negative number/);
    expect((await run()).code).toBe(2);
  });

  it("prints its version", async () => {
    expect((await run("--version")).out.trim()).toBe("0.1.0");
  });
});
