import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer, request } from "node:http";
import { afterEach, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createHttpServer, type HttpServerHandle } from "../http.js";

const token = randomUUID();
const originalEnv = { ...process.env };
let http: HttpServerHandle | undefined;
const connections: { client: Client; transport: StreamableHTTPClientTransport }[] = [];
afterEach(async () => {
  for (const { client, transport } of connections.splice(0)) {
    await transport.terminateSession().catch(() => undefined);
    await client.close();
  }
  await http?.close();
  http = undefined;
  process.env = { ...originalEnv };
});
function configure() {
  process.env.HOTWASH_URL = "http://example.invalid";
  process.env.HOTWASH_API_KEY = "test-upstream-key-at-least-32-characters";
  process.env.HOTWASH_MCP_HTTP_TOKEN = token;
  process.env.HOTWASH_MCP_HTTP_PORT = "0";
  process.env.HOTWASH_MCP_HTTP_HOST = "127.0.0.1";
}
async function start() {
  http = await createHttpServer();
  return `http://127.0.0.1:${http.port}`;
}
async function connect(url: string) {
  const transport = new StreamableHTTPClientTransport(new URL(`${url}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  const client = new Client({ name: "http-test", version: "1" });
  connections.push({ client, transport });
  await client.connect(transport);
  return { client, transport };
}

for (const authorization of [undefined, "Bearer wrong-token"]) {
  test(`rejects invalid authentication: ${authorization}`, async () => {
    configure();
    const response = await fetch(`${await start()}/mcp`, {
      method: "POST", headers: authorization ? { authorization } : {},
    });
    assert.equal(response.status, 401);
    assert.equal(response.headers.get("www-authenticate"), "Bearer");
  });
}
test("health exposes only liveness without a token", async () => {
  configure();
  const response = await fetch(`${await start()}/healthz`);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '{"status":"ok"}');
});
test("lists tools and invalidates a terminated session", async () => {
  configure();
  const url = await start();
  const { client, transport } = await connect(url);
  const { tools } = await client.listTools();
  assert.ok(tools.some(t => t.name === "hotwash_start_run"));
  for (const tool of tools) {
    assert.equal("$schema" in tool.inputSchema, false);
    if (tool.outputSchema) assert.equal("$schema" in tool.outputSchema, false);
  }
  const id = transport.sessionId!;
  assert.ok(id);
  await transport.terminateSession();
  const response = await fetch(`${url}/mcp`, {
    headers: { authorization: `Bearer ${token}`, "mcp-session-id": id, accept: "text/event-stream" },
  });
  assert.equal(response.status, 404);
});
for (const headers of [
  { origin: "https://evil.example.com" }, { origin: "null" },
  { origin: "http://localhost.evil.example.com" }, { host: "evil.example.com" },
  { host: "localhost@evil.example.com" },
]) {
  test(`rejects rebinding headers before authentication: ${JSON.stringify(headers)}`, async () => {
    configure();
    const status = await new Promise<number | undefined>((resolve, reject) => {
      void start().then(url => {
        const req = request(`${url}/mcp`, { method: "POST", headers }, res => {
          res.resume(); res.on("end", () => resolve(res.statusCode));
        });
        req.on("error", reject); req.end();
      }, reject);
    });
    assert.equal(status, 403);
  });
}
for (const value of [undefined, "", "   ", "test-upstream-key-at-least-32-characters", "url-user-at-least-32-characters-long", "url-password-at-least-32-characters"]) {
  test(`refuses missing, blank, or upstream HTTP token: ${JSON.stringify(value)}`, async () => {
    configure();
    process.env.HOTWASH_URL = "https://url-user-at-least-32-characters-long:url-password-at-least-32-characters@example.invalid";
    if (value === undefined) delete process.env.HOTWASH_MCP_HTTP_TOKEN;
    else process.env.HOTWASH_MCP_HTTP_TOKEN = value;
    await assert.rejects(createHttpServer(), /HOTWASH_MCP_HTTP_TOKEN/);
  });
}
test("refuses a token shorter than 32 characters", async () => {
  configure();
  process.env.HOTWASH_MCP_HTTP_TOKEN = "a".repeat(31);
  await assert.rejects(start(), /at least 32 characters/);
});
for (const host of ["0.0.0.0", "::", "[::]"]) {
  test(`refuses wildcard bind host ${host}`, async () => {
    configure();
    process.env.HOTWASH_MCP_HTTP_HOST = host;
    await assert.rejects(start(), /not a wildcard/);
  });
}
test("accepts a token with surrounding whitespace from a secrets file", async () => {
  configure();
  process.env.HOTWASH_MCP_HTTP_TOKEN = `  ${token}\n`;
  const { client } = await connect(await start());
  assert.ok((await client.listTools()).tools.some(tool => tool.name === "hotwash_start_run"));
});
for (const port of ["-1", "65536", "abc", "1.5", "3118suffix"]) {
  test(`refuses invalid port ${port}`, async () => {
    configure(); process.env.HOTWASH_MCP_HTTP_PORT = port;
    await assert.rejects(createHttpServer(), /HOTWASH_MCP_HTTP_PORT/);
  });
}
for (const chunked of [false, true]) {
  test(`limits request bytes (chunked=${chunked})`, async () => {
    configure(); const url = await start();
    const status = await new Promise<number | undefined>((resolve, reject) => {
      const req = request(`${url}/mcp`, {
        method: "POST", headers: { authorization: `Bearer ${token}`,
          ...(chunked ? {} : { "content-length": "1200000" }) },
      }, res => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
      req.on("error", reject);
      req.write("x".repeat(600000)); req.end("x".repeat(600000));
    });
    assert.equal(status, 413);
  });
}
test("separate sessions target explicit backend runs and cannot borrow confirmation", async () => {
  configure();
  process.env.HOTWASH_MCP_ALLOW_MUTATIONS = "true";
  const requests: string[] = [];
  const backend = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    req.resume();
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ execution: { id: 42 }, steps: [], already_accepted: false }));
  });
  await new Promise<void>(resolve => backend.listen(0, "127.0.0.1", resolve));
  const address = backend.address();
  assert.ok(address && typeof address !== "string");
  process.env.HOTWASH_URL = `http://127.0.0.1:${address.port}`;
  try {
    const url = await start();
    const [a, b] = await Promise.all([connect(url), connect(url)]);
    assert.notEqual(a.transport.sessionId, b.transport.sessionId);
    assert.equal((await a.client.callTool({ name: "hotwash_accept_suggestion", arguments: { suggestion_id: 7, confirm: true } })).isError, undefined);
    for (const client of [b.client, a.client]) {
      assert.equal((await client.callTool({ name: "hotwash_accept_suggestion", arguments: { suggestion_id: 7 } })).isError, true);
      assert.equal((await client.callTool({ name: "hotwash_cancel_run", arguments: { execution_id: 42 } })).isError, true);
      assert.equal((await client.callTool({ name: "hotwash_dismiss_suggestion", arguments: { suggestion_id: 7 } })).isError, true);
    }
    await a.client.callTool({ name: "hotwash_advance_step", arguments: { execution_id: 42, node_id: "collect", status: "completed" } });
    await b.client.callTool({ name: "hotwash_query_run", arguments: { execution_id: 42 } });
    await b.client.callTool({ name: "hotwash_advance_step", arguments: { execution_id: 99, node_id: "triage", status: "in_progress" } });
    // A filename or opaque reference never supplies bytes from the HTTP host.
    assert.equal((await b.client.callTool({ name: "hotwash_attach_artifact", arguments: {
      execution_id: 99, node_id: "triage", filename: "/etc/passwd", source_ref: "file:///etc/passwd",
    } })).isError, true);
    assert.deepEqual(requests, ["POST /api/ingest/suggestions/7/accept?confirm=true",
      "PATCH /api/executions/42/steps/collect", "GET /api/executions/42",
      "PATCH /api/executions/99/steps/triage"]);
  } finally {
    await new Promise<void>((resolve, reject) => backend.close(error => error ? reject(error) : resolve()));
  }
});
test("closes active sessions and the listener idempotently", async () => {
  configure(); const url = await start(); await connect(url);
  await Promise.all([http!.close(), http!.close()]);
  await assert.rejects(fetch(`${url}/healthz`));
});
