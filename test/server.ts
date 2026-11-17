import { createHash } from "node:crypto";
import { createServer, type OutgoingHttpHeaders, type Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";

export interface Route {
  status?: number;
  headers?: OutgoingHttpHeaders;
  body?: string;
  hang?: boolean;
  stream?: boolean;
  before?: () => Promise<unknown>;
}

export interface TestServer {
  port: number;
  url: (path: string) => string;
  hits: (path: string) => number;
  waitForHit: (path: string) => Promise<void>;
  close: () => Promise<void>;
}

export function html(head: string, body = "<p>hello</p>"): string {
  return `<!doctype html><html><head>${head}</head><body>${body}</body></html>`;
}

export async function startServer(routes: Record<string, Route>): Promise<TestServer> {
  const hits = new Map<string, number>();
  const waiting = new Map<string, (() => void)[]>();
  const upgraded = new Set<Socket>();
  const hit = (path: string) => {
    hits.set(path, (hits.get(path) ?? 0) + 1);
    for (const resolve of waiting.get(path) ?? []) resolve();
    waiting.delete(path);
  };

  const server: Server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    hit(path);
    const route = routes[path];
    if (!route) {
      response.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    if (route.hang) return;
    await route.before?.();
    response.writeHead(route.status ?? 200, { "content-type": "text/html; charset=utf-8", ...route.headers });
    if (route.stream) response.write(route.body ?? "");
    else response.end(route.body ?? html(""));
  });
  server.on("upgrade", (request, socket: Socket) => {
    hit(new URL(request.url ?? "/", "http://localhost").pathname);
    upgraded.add(socket);
    const accept = createHash("sha1").update(`${request.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on("error", () => {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    url: (path) => `http://127.0.0.1:${port}${path}`,
    hits: (path) => hits.get(path) ?? 0,
    waitForHit: (path) =>
      hits.has(path) ? Promise.resolve() : new Promise((resolve) => waiting.set(path, [...(waiting.get(path) ?? []), resolve])),
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
        for (const socket of upgraded) socket.destroy();
      }),
  };
}
