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

## Command line

```console
$ npx no-phone-home [options] <url>...

  -a, --allow <host>     Allow this host too; "*.example.com" allows subdomains (repeatable)
      --timeout <ms>     Give up on a page after this long (default 30000)
      --json             Print the full reports as JSON
  -q, --quiet            Print nothing; use the exit code
```

Exit codes: `0` every page passed, `1` a page can contact another host, `2` error.

## Library

```js
import { checkUrl, evaluatePolicies, parsePolicyList } from "no-phone-home";

const report = await checkUrl("https://app.example.com", { allow: ["api.example.com"] });
report.ok; // false
report.findings; // [{ directive: "connect-src", reaches: "any host", via: ["https:"], governs: "..." }]

const policies = parsePolicyList("default-src 'self'; form-action 'self'", "header");
evaluatePolicies(policies, { pageUrl: "https://app.example.com" }); // []
```

## Limits

The policy is only one piece. Today the tool reads the policy and does not run the page.

- **Navigation.** No CSP directive can stop a script from changing `location` or opening a window to another site.
- **Workers.** A service worker or web worker gets its own policy, from the headers on its script, and this version doesn't check it yet.
- **Policies set by JavaScript.** Only the server's response is read, so a meta tag that a script inserts later is not seen.

## Roadmap

- Load each page in a real browser and record every request it makes, including WebSockets and beacons.
- Check the policy each service worker and web worker actually gets.
- Serve a static build folder and crawl its pages, so it can run before anything is deployed.
- Click through each page so that requests made after interaction are caught too.
- A GitHub Action.

## License

MIT
