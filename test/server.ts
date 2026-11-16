import { createServer, type OutgoingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface Route {
  status?: number;
  headers?: OutgoingHttpHeaders;
  body?: string;
  hang?: boolean;
}

export interface TestServer {
  url: (path: string) => string;
  close: () => Promise<void>;
}

export function html(head: string, body = "<p>hello</p>"): string {
  return `<!doctype html><html><head>${head}</head><body>${body}</body></html>`;
}

export async function startServer(routes: Record<string, Route>): Promise<TestServer> {
  const server: Server = createServer((request, response) => {
    const route = routes[new URL(request.url ?? "/", "http://localhost").pathname];
    if (!route) {
      response.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    if (route.hang) return;
    response.writeHead(route.status ?? 200, { "content-type": "text/html; charset=utf-8", ...route.headers });
    response.end(route.body ?? html(""));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: (path) => `http://127.0.0.1:${port}${path}`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      }),
  };
}
