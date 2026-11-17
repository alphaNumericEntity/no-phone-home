# no-phone-home

Fail CI when a web page can contact a host you didn't allow.

"Your data never leaves your browser" is easy to write on a landing page and hard to check. Watching one page load in DevTools shows what the page did that time, not what it *can* do. The thing that decides what it can do is the Content-Security-Policy the server sends. `no-phone-home` reads that policy and reports every way it still lets the page reach another host.

```console
$ npx no-phone-home https://example.com
https://example.com/: FAIL: no Content-Security-Policy is enforced, so the page can contact any host

$ npx no-phone-home --allow api.example.com https://app.example.com
https://app.example.com/: FAIL: the page can contact hosts outside the allowlist
  connect-src (fetch, XHR, WebSocket, EventSource and sendBeacon): any host, via "https:"
  img-src (images, including tracking pixels): www.google-analytics.com
  form-action (form submissions): any host, via no form-action directive
```

## What it checks

It fetches each URL, then reads the policies from the `Content-Security-Policy` header and from `<meta http-equiv>` tags. For each way a page can send a request, it works out which hosts every enforced policy allows:

| Directive | Covers |
|---|---|
| `connect-src` | fetch, XHR, WebSocket, EventSource and `sendBeacon` |
| `script-src-elem` | scripts |
| `style-src-elem` | stylesheets |
| `img-src` | images, including tracking pixels |
| `font-src` | web fonts |
| `media-src` | audio and video |
| `frame-src` | iframes |
| `object-src` | `<object>` and `<embed>` |
| `manifest-src` | the web app manifest |
| `form-action` | form submissions |
| `report-uri`, `report-to` | where violation reports are sent |

Its rules follow what browsers actually do:

- **Fallbacks.** Each directive falls back the way the CSP spec says: `script-src-elem` to `script-src` to `default-src`, and `frame-src` to `child-src` to `default-src`. `form-action` has no fallback, so `default-src 'self'` alone still lets a form post anywhere.
- **Sources that allow any host.** `*`, `https:`, `wss:` and similar bare schemes count as any host, and so does `'strict-dynamic'` in a script directive, because scripts it trusts can load scripts from anywhere.
- **Several policies.** When a page has more than one policy (headers, or a header and a meta tag), a request has to pass all of them, so only the hosts that every policy allows are reported.
- **Meta tags.** A `<meta>` policy outside `<head>` is ignored, as browsers ignore it. One that comes after a script or stylesheet tag is reported as a warning, because that resource loads before the policy applies.
- **Report-only policies.** `Content-Security-Policy-Report-Only` is listed, but it doesn't count, because it blocks nothing.

Hosts are compared by name. The page's own host is always allowed. `--allow *.example.com` allows every subdomain of `example.com`, but not `example.com` itself.

## Browser mode

The policy says what a page *can* reach. `--browser` also loads the page in headless Chromium and records what it *did* reach. Both views are printed together, one after the other:

```console
$ npx no-phone-home --browser https://github.com
https://github.com -> https://github.com/: FAIL: the page can contact hosts outside the allowlist
  connect-src (fetch, XHR, WebSocket, EventSource and sendBeacon): uploads.github.com, www.githubstatus.com, collector.github.com, raw.githubusercontent.com and 54 more
  script-src-elem (scripts): github.githubassets.com
  ...
https://github.com -> https://github.com/: FAIL: in Chromium, the page contacted 3 other hosts
  github.githubassets.com: 109 requests (60 script, 26 stylesheet, 19 image, 2 font, 1 media, 1 fetch, 1 failed)
  images.ctfassets.net: 4 requests (4 image)
  collector.github.com: 3 requests (3 beacon)

$ npx no-phone-home --browser https://pdfairlock.com
https://pdfairlock.com -> https://pdfairlock.com/: PASS: the Content-Security-Policy keeps every request on pdfairlock.com and the allowed hosts
https://pdfairlock.com -> https://pdfairlock.com/: PASS: in Chromium, every request stayed on pdfairlock.com and the allowed hosts (406 requests)
```

With `--browser`, a page passes only when both views pass: its policy keeps it on its own host and the allowed hosts, and every request it made in Chromium stayed there too. A page with no policy fails even if the recording was clean, because nothing stops it contacting other hosts later.

### Install

Browser mode runs on [Playwright](https://playwright.dev). `playwright-core` comes with `no-phone-home` as an optional dependency, but Chromium itself is a separate download:

```console
$ npm install --save-dev no-phone-home
$ npx playwright-core install chromium              # macOS, Windows
$ npx playwright-core install --with-deps chromium  # Linux CI, which also needs system libraries
```

Without Chromium, or with optional dependencies left out, `--browser` exits `2` and prints the exact install command for the version it found. Checking the policy alone never needs a browser.

### What it records

It waits for the page's `load` event and for the network to go quiet, then for `--wait <ms>` more if you set it. Everything Chromium reports in that time counts, from the page, its iframes, pop-ups, dedicated workers and service workers:

- the page itself and any redirects, scripts, stylesheets, images, fonts, audio and video, the manifest;
- `fetch`, XHR, `EventSource`, WebSocket connections, `navigator.sendBeacon` and violation reports.

Each host other than the page's own (and the host of the URL you gave, if it redirected) and the `--allow` hosts is listed with its request count by type. Requests that went out and then failed still count, because they reached the network. Requests the Content-Security-Policy refused are listed separately as blocked: the browser never sent them. Those refusals come from Chromium's failed-request events and from `securitypolicyviolation` events in the page and its frames, so a refused `fetch`, beacon or WebSocket is reported under the directive that refused it (`connect-src`).

### What it doesn't record

- **Anything after the wait.** It sees one load with no clicks or typing. A request made later, or only after interaction, isn't recorded.
- **Beacons sent while the page is being left.** Chromium sends a beacon fired on `pagehide`, `visibilitychange` or `unload` after the page is gone, and Playwright never reports it. The policy check covers these: `connect-src` governs `sendBeacon` at any time.
- **Shared workers.** Playwright doesn't expose them, so their requests are missed.
- **Refusals inside workers.** A worker's own policy can refuse a request. That request isn't counted as contacted, which is correct, but it isn't listed as blocked either.
- **Connections that aren't requests.** `<link rel="preconnect">` and `dns-prefetch` hints, and WebRTC, aren't recorded. A CORS preflight isn't listed separately, but the request it was for is.
- **What other visitors see.** It runs one headless Chromium from your machine. A site can serve other browsers, regions or signed-in users different content. Scripts that wait for a cookie banner to be accepted don't run.

## Command line

```console
$ npx no-phone-home [options] <url>...

  -a, --allow <host>     Allow this host too; "*.example.com" allows subdomains (repeatable)
      --browser          Also load each page in headless Chromium and report every host it contacted
      --wait <ms>        With --browser, keep recording this long after the network goes idle (default 0)
      --timeout <ms>     Give up on a page after this long (default 30000)
      --json             Print the full reports as JSON
  -q, --quiet            Print nothing; use the exit code
```

Exit codes: `0` every page passed, `1` a page can contact another host, `2` error. With `--browser`, a page passes only when its policy passes and every request it made stayed on its own host and the allowed hosts.

With `--json`, each result has the policy `report`, and with `--browser` a `browser` report as well: `contacted` and `blocked` hosts with their counts, and every recorded request (`url`, `host`, `type`, `from`, and `blocked` or `error` where they apply).

## Library

```js
import { checkUrl, evaluatePolicies, parsePolicyList, recordUrl } from "no-phone-home";

const report = await checkUrl("https://app.example.com", { allow: ["api.example.com"] });
report.ok; // false
report.findings; // [{ directive: "connect-src", reaches: "any host", via: ["https:"], governs: "..." }]

const policies = parsePolicyList("default-src 'self'; form-action 'self'", "header");
evaluatePolicies(policies, { pageUrl: "https://app.example.com" }); // []

const recording = await recordUrl("https://app.example.com", { allow: ["api.example.com"], waitMs: 1000 });
recording.contacted; // [{ host: "www.google-analytics.com", requests: 2, types: { beacon: 2 }, failed: 0 }]
```

`recordUrl` launches Chromium for one page. To record several pages, use `openRecorder()`, call its `record()` once per page, then call `close()`.

## Limits

The policy is only one piece. The limits of browser mode are listed [above](#what-it-doesnt-record).

- **Navigation.** No CSP directive can stop a script from changing `location` or opening a window to another site.
- **Workers.** A service worker or web worker gets its own policy, from the headers on its script, and this version doesn't check it yet.
- **Policies set by JavaScript.** Only the server's response is read, so a meta tag that a script inserts later is not seen.

## Roadmap

- Check the policy each service worker and web worker actually gets.
- Serve a static build folder and crawl its pages, so it can run before anything is deployed.
- Click through each page so that requests made after interaction are caught too.
- A GitHub Action.

## License

MIT
