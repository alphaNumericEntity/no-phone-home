import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { serveDirectory } from "../src/index.js";
import { runCli } from "./run.js";

const STRICT = "default-src 'self'; form-action 'self'";
const OPEN = "default-src 'self'; form-action 'self'; connect-src 'self' api.example.com";

const made: string[] = [];

async function folder(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "nph-serve-"));
  made.push(root);
  for (const [path, text] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), text);
  }
  return root;
}

afterAll(() => Promise.all(made.map((root) => rm(root, { recursive: true, force: true }))));

const page = (head = "") => `<!doctype html><html><head>${head}</head><body>hi</body></html>`;

function vercel(config: object): string {
  return JSON.stringify(config);
}

async function json(...args: string[]) {
  const { code, out, err } = await runCli(["--json", ...args]);
  const results = JSON.parse(out) as { url: string; report: { ok: boolean; policies: { text: string }[] } }[];
  const byPath = Object.fromEntries(results.map((r) => [new URL(r.url).pathname, r.report]));
  return { code, err, byPath, paths: results.map((r) => new URL(r.url).pathname) };
}

describe("--serve with a vercel.json", () => {
  it("applies the header rules in order, the last one winning, at the clean URLs", async () => {
    const dir = await folder({
      "index.html": page(),
      "about.html": page(),
      "docs/index.html": page(),
      "docs/api.html": page(),
      "open.html": page(),
    });
    const config = await folder({
      "vercel.json": vercel({
        cleanUrls: true,
        headers: [
          { source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: STRICT }] },
          { source: "/open", headers: [{ key: "content-security-policy", value: OPEN }] },
          { source: "/About", headers: [{ key: "Content-Security-Policy", value: OPEN }] },
        ],
      }),
    });
    const { code, byPath, paths, err } = await json("--serve", dir, "--headers", join(config, "vercel.json"));
    expect(paths).toEqual(["/", "/about", "/docs", "/docs/api", "/open", "/open/"]);
    expect(byPath["/open/"]!.ok).toBe(true);
    expect(code).toBe(1);
    expect(byPath["/open"]!.policies.map((p) => p.text)).toEqual([OPEN]);
    expect(byPath["/about"]!.ok).toBe(true);
    expect(byPath["/docs/api"]!.ok).toBe(true);
    expect(err).toContain("with the headers from");
  });

  it("requests the URL forms that cleanUrls and trailingSlash give", async () => {
    const dir = await folder({ "index.html": page(), "a.html": page(), "b/index.html": page() });
    const config = await folder({
      "plain.json": vercel({}),
      "slash.json": vercel({ cleanUrls: true, trailingSlash: true }),
      "noslash.json": vercel({ trailingSlash: false }),
    });
    expect((await json("--serve", dir, "--headers", join(config, "plain.json"))).paths).toEqual(["/", "/a.html", "/b/"]);
    expect((await json("--serve", dir, "--headers", join(config, "slash.json"))).paths).toEqual(["/", "/a/", "/b/"]);
    expect((await json("--serve", dir, "--headers", join(config, "noslash.json"))).paths).toEqual(["/", "/a.html", "/b"]);
  });

  it("fills named segments into header names and values", async () => {
    const dir = await folder({ "api/index.html": page(), "content-security-policy/index.html": page() });
    const config = await folder({
      "vercel.json": vercel({
        headers: [
          { source: "/:name/", headers: [{ key: "Content-Security-Policy", value: "default-src 'self'; form-action 'self'; connect-src :name.example.com" }] },
          { source: "/:header/", headers: [{ key: ":header", value: STRICT }] },
        ],
      }),
    });
    const { byPath } = await json("--serve", dir, "--headers", join(config, "vercel.json"));
    expect(byPath["/api/"]!.policies[0]!.text).toContain("connect-src api.example.com");
    expect(byPath["/content-security-policy/"]!.policies.map((p) => p.text)).toEqual([STRICT]);
  });

  it("also checks the other slash form when trailingSlash is unset and its headers differ", async () => {
    const dir = await folder({ "index.html": page(), "docs/index.html": page(), "about.html": page(), "same.html": page() });
    const config = await folder({
      "vercel.json": vercel({
        cleanUrls: true,
        headers: [
          { source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: STRICT }] },
          { source: "/about/", headers: [{ key: "Content-Security-Policy", value: OPEN }] },
          { source: "/docs", headers: [{ key: "Content-Security-Policy", value: OPEN }] },
        ],
      }),
    });
    const { code, byPath, paths, err } = await json("--serve", dir, "--headers", join(config, "vercel.json"));
    expect(paths).toEqual(["/", "/about", "/about/", "/docs", "/docs/", "/same"]);
    expect(byPath["/about"]!.ok).toBe(true);
    expect(byPath["/about/"]!.ok).toBe(false);
    expect(byPath["/docs"]!.ok).toBe(false);
    expect(byPath["/docs/"]!.ok).toBe(true);
    expect(code).toBe(1);
    expect(err).toContain("/about is also served at /about/, with different policy headers, so both are checked");
  });

  it("says when two files are served at the same clean URL", async () => {
    const dir = await folder({ "about.html": page(), "about/index.html": page() });
    const config = await folder({ "vercel.json": vercel({ cleanUrls: true }) });
    const { paths, err } = await json("--serve", dir, "--headers", join(config, "vercel.json"));
    expect(paths).toEqual(["/about"]);
    expect(err).toContain("about.html and about/index.html would both be served at /about; only about.html is checked there");
  });

  it("checks the literal index.html path when cleanUrls is off and only its policy differs", async () => {
    const dir = await folder({ "index.html": page(), "docs/index.html": page(), "cached/index.html": page() });
    const config = await folder({
      "vercel.json": vercel({
        trailingSlash: true,
        headers: [
          { source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: STRICT }] },
          { source: "/docs/index.html", headers: [{ key: "Content-Security-Policy", value: OPEN }] },
          { source: "/cached/index.html", headers: [{ key: "Cache-Control", value: "no-store" }] },
        ],
      }),
    });
    const { byPath, paths } = await json("--serve", dir, "--headers", join(config, "vercel.json"));
    expect(paths).toEqual(["/", "/cached/", "/docs/", "/docs/index.html"]);
    expect(byPath["/docs/index.html"]!.ok).toBe(false);
  });

  it("skips a rule with a has or missing condition and says so", async () => {
    const dir = await folder({ "index.html": page() });
    const config = await folder({
      "vercel.json": vercel({
        headers: [
          { source: "/(.*)", headers: [{ key: "Content-Security-Policy", value: STRICT }] },
          { source: "/(.*)", has: [{ type: "host", value: "example.com" }], headers: [{ key: "Content-Security-Policy", value: OPEN }] },
        ],
        routes: [{ src: "/(.*)", headers: { "Content-Security-Policy": OPEN } }],
      }),
    });
    const { code, err } = await json("--serve", dir, "--headers", join(config, "vercel.json"));
    expect(code).toBe(0);
    expect(err).toContain('vercel.json: headers[1] (/(.*)) has a "has" or "missing" condition');
    expect(err).toContain('vercel.json: "routes" is not read');
  });

  it("exits 2 on a config it can't read", async () => {
    const dir = await folder({ "index.html": page() });
    const config = await folder({
      "broken.json": "{",
      "nosource.json": vercel({ headers: [{ headers: [] }] }),
      "badpattern.json": vercel({ headers: [{ source: "/(", headers: [] }] }),
      "netlify.toml": "",
    });
    for (const [file, message] of [
      ["broken.json", "broken.json is not valid JSON"],
      ["nosource.json", 'nosource.json: headers[0].source must be a path starting with "/"'],
      ["badpattern.json", 'badpattern.json: headers[0].source "/(" is not a valid pattern'],
      ["netlify.toml", "netlify.toml is not read"],
      ["missing.json", "can't read"],
    ] as const) {
      const { code, err } = await runCli(["--serve", dir, "--headers", join(config, file)]);
      expect(code, file).toBe(2);
      expect(err, file).toContain(message);
    }
  });
});

describe("--serve with a _headers file", () => {
  it("finds the folder's _headers, joins repeated headers and honours detaches", async () => {
    const dir = await folder({
      _headers: [
        "# every page",
        "/*",
        `  Content-Security-Policy: ${STRICT}`,
        "  X-Frame-Options: DENY",
        "/blog/:post",
        "  Content-Security-Policy: img-src 'self' cdn.example.com",
        "/legacy",
        "  ! Content-Security-Policy",
        "https://:project.pages.dev/*",
        `  Content-Security-Policy: ${OPEN}`,
      ].join("\n"),
      "index.html": page(),
      "legacy.html": page(),
      "blog/first.html": page(),
      "blog/index.html": page(),
    });
    const { code, byPath, paths, err } = await json("--serve", dir);
    expect(paths).toEqual(["/", "/blog/", "/blog/first", "/legacy"]);
    expect(code).toBe(1);
    expect(byPath["/"]!.ok).toBe(true);
    expect(byPath["/blog/"]!.ok).toBe(true);
    expect(byPath["/blog/first"]!.policies.map((p) => p.text)).toEqual([STRICT, "img-src 'self' cdn.example.com"]);
    expect(byPath["/blog/first"]!.ok).toBe(true);
    expect(byPath["/legacy"]!.policies).toEqual([]);
    expect(err).toContain('_headers: the rule for "https://:project.pages.dev/*" names a host');
  });

  it("reads the file the way Cloudflare's parser does", async () => {
    const filler = Array.from({ length: 97 }, (_, i) => `/filler-${i}\n  X-Filler: ${i}`);
    const dir = await folder({
      _headers: [
        "X-Stray: before any path",
        "/unindented",
        `Content-Security-Policy: ${STRICT}`,
        "/same-rule",
        `  Content-Security-Policy: ${STRICT}`,
        "  ! Content-Security-Policy",
        "/no-space",
        `  Content-Security-Policy: ${STRICT}`,
        "/no-space",
        `  Content-Security-Policy: ${STRICT}`,
        "  !Content-Security-Policy",
        "/long",
        `  Content-Security-Policy: ${STRICT}; img-src 'self' ${"'sha256-x' ".repeat(200)}`,
        ...filler,
        "/past-the-limit",
        `  Content-Security-Policy: ${STRICT}`,
      ].join("\r\n"),
      "unindented.html": page(),
      "same-rule.html": page(),
      "no-space.html": page(),
      "long.html": page(),
      "past-the-limit.html": page(),
    });
    const { byPath, err } = await json("--serve", dir);
    expect(byPath["/unindented"]!.ok).toBe(true);
    expect(byPath["/same-rule"]!.ok).toBe(true);
    expect(byPath["/no-space"]!.policies.map((p) => p.text)).toEqual([STRICT]);
    expect(byPath["/long"]!.policies).toEqual([]);
    expect(byPath["/past-the-limit"]!.policies).toEqual([]);
    expect(err).toContain('_headers line 1: "X-Stray: before any path" comes before any path, so it is ignored');
    expect(err).toContain('_headers line 11: expected "Name: value" or "! Name", got "!Content-Security-Policy"');
    expect(err).toContain("_headers line 13 is longer than 2000 characters");
    expect(err).toContain("_headers line 208: Cloudflare stops reading after 101 rules");
  });
});

describe("--serve --host netlify", () => {
  it("lets a later rule replace a header and matches paths as Netlify does", async () => {
    const dir = await folder({
      _headers: [
        "/*",
        `  Content-Security-Policy: ${STRICT}`,
        "/Blog/*",
        `  Content-Security-Policy: ${OPEN}`,
        "/legacy",
        "  ! Content-Security-Policy",
      ].join("\n"),
      "index.html": page(),
      "blog/index.html": page(),
      "blog/first.html": page(),
      "legacy.html": page(),
    });
    const netlify = await json("--serve", dir, "--host", "netlify");
    expect(netlify.byPath["/blog/"]!.policies.map((p) => p.text)).toEqual([OPEN]);
    expect(netlify.byPath["/blog/first"]!.policies.map((p) => p.text)).toEqual([OPEN]);
    expect(netlify.byPath["/legacy"]!.ok).toBe(true);
    expect(netlify.err).toContain('"! Content-Security-Policy" has no colon, so Netlify ignores it');
    const cloudflare = await json("--serve", dir);
    expect(cloudflare.byPath["/blog/first"]!.policies.map((p) => p.text)).toEqual([STRICT]);
    expect(cloudflare.byPath["/legacy"]!.policies).toEqual([]);
  });

  it("sends the header Netlify sends when names differ only in case, and keeps regex characters around *", async () => {
    const dir = await folder({
      _headers: [
        "/*",
        `  Content-Security-Policy: ${STRICT}`,
        "/blog/*",
        `  content-security-policy: ${OPEN}`,
        "/blog/x",
        `  Content-Security-Policy: ${STRICT}`,
        "/v1.*",
        `  Content-Security-Policy: ${OPEN}`,
        "/bad",
        "  X Foo: bar",
      ].join("\n"),
      "blog/x.html": page(),
      "v1x2.html": page(),
      "bad.html": page(),
    });
    const { byPath, err } = await json("--serve", dir, "--host", "netlify");
    expect(byPath["/blog/x"]!.policies.map((p) => p.text)).toEqual([OPEN]);
    expect(byPath["/v1x2"]!.policies.map((p) => p.text)).toEqual([OPEN]);
    expect(byPath["/bad"]!.ok).toBe(true);
    expect(err).toContain('_headers line 10: "X Foo: bar" is not a valid HTTP header, so it is ignored');
  });

  it("rejects --host without a _headers file or with a vercel.json", async () => {
    const dir = await folder({ "index.html": page() });
    const config = await folder({ "vercel.json": vercel({}) });
    for (const [args, message] of [
      [["--serve", dir, "--host", "netlify"], "--host netlify needs a _headers file"],
      [["--serve", dir, "--host", "netlify", "--headers", join(config, "vercel.json")], "--host applies to a _headers file, not to vercel.json"],
      [["--serve", dir, "--host", "github"], '--host must be "cloudflare" or "netlify", got "github"'],
      [["--host", "netlify", "https://example.com"], "--host only applies with --serve"],
    ] as const) {
      const { code, err } = await runCli([...args]);
      expect(code, message).toBe(2);
      expect(err).toContain(message);
    }
  });
});

describe("--serve", () => {
  it("checks <meta> policies when there is no header config", async () => {
    const dir = await folder({
      "index.html": page(`<meta http-equiv="Content-Security-Policy" content="${STRICT}">`),
      "open.html": page(),
    });
    const { code, out, err } = await runCli(["--serve", dir]);
    expect(code).toBe(1);
    expect(err).toContain("only <meta> policies are checked");
    expect(out).toMatch(/\/: PASS/);
    expect(out).toMatch(/\/open: FAIL: no Content-Security-Policy/);
    expect(out).toContain("Checked 2 pages: 1 passed, 1 failed\n");
  });

  it("checks worker scripts under the headers their own path gets", async () => {
    const dir = await folder({
      _headers: `/*\n  Content-Security-Policy: ${STRICT}\n/open-worker.js\n  ! Content-Security-Policy\n`,
      "index.html": page(),
      "worker.js": "",
      "open-worker.js": "",
    });
    expect((await runCli(["--serve", dir, "--worker", "/worker.js"])).code).toBe(0);
    const { code, out } = await runCli(["--serve", dir, "--worker", "/open-worker.js"]);
    expect(code).toBe(1);
    expect(out).toMatch(/open-worker\.js \(worker\): FAIL: the script is served without a Content-Security-Policy/);
  });

  it("serves files the way a static host does and nothing outside the folder", async () => {
    const outside = await folder({ "secret.html": "secret" });
    const dir = await folder({ "index.html": page(), "a.html": "a", "b/index.html": "b", "app.wasm": "", "404.html": "missing", "c #1.html": "c", _headers: "/a\n  X-Test: 1\n" });
    const site = await serveDirectory(dir);
    try {
      const get = async (path: string) => {
        const response = await fetch(site.url + path);
        return [response.status, await response.text(), response.headers.get("content-type")];
      };
      expect(site.pages).toEqual(["/", "/404", "/a", "/b/", "/c%20%231"]);
      expect(await get("/c%20%231")).toEqual([200, "c", "text/html; charset=utf-8"]);
      expect(await get("/a")).toEqual([200, "a", "text/html; charset=utf-8"]);
      expect(await get("/a.html")).toEqual([200, "a", "text/html; charset=utf-8"]);
      expect(await get("/b")).toEqual([200, "b", "text/html; charset=utf-8"]);
      expect((await get("/app.wasm"))[2]).toBe("application/wasm");
      expect(await get("/nope")).toEqual([404, "missing", "text/html; charset=utf-8"]);
      expect((await get("/_headers"))[0]).toBe(404);
      const name = basename(outside);
      expect((await get(`/..%2F${name}%2Fsecret.html`))[1]).not.toBe("secret");
      expect((await get(`/%2E%2E/${name}/secret.html`))[1]).not.toBe("secret");
    } finally {
      await site.close();
    }
  });

  it("rejects options that don't fit together and folders it can't check", async () => {
    const empty = await folder({ "readme.txt": "" });
    for (const [args, message] of [
      [["--headers", "vercel.json", "https://example.com"], "--headers only applies with --serve"],
      [["--serve", empty, "https://example.com"], "pass either --serve or URLs, not both"],
      [["--serve", join(empty, "nope")], "is not a folder"],
      [["--serve", empty], "has no .html files"],
    ] as const) {
      const { code, err } = await runCli([...args]);
      expect(code, message).toBe(2);
      expect(err).toContain(message);
    }
  });
});
