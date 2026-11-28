import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const entry = fileURLToPath(new URL("../index.ts", import.meta.url));
const newer = {
  id: 42, incident_title: "Synthetic incident", incident_id: "TEST-42",
  playbook_title: "Synthetic playbook", playbook_id: 7, status: "active",
  steps_total: 5, steps_completed: 2,
  started_at: "2026-11-28T10:00:00Z", completed_at: null,
};
const older = { ...newer, id: 41, status: "completed", steps_completed: 5,
  started_at: "2026-11-27T10:00:00Z", completed_at: "2026-11-27T11:00:00Z" };

// Decode the existing untrusted-data envelope only to inspect test results.
function data(result: Awaited<ReturnType<Client["callTool"]>>) {
  assert.notEqual(result.isError, true);
  const envelope = result.structuredContent as { warning: string; untrusted_data: string };
  assert.match(envelope.warning, /Untrusted Hotwash/);
  return JSON.parse(envelope.untrusted_data.split("\n").slice(1, -1).join("\n"));
}

for (const mode of ["stdio", "http"] as const) {
  test(`list runs through public ${mode} entry point`, { timeout: 30000 }, async (t) => {
    const seen: string[] = [];
    let response: unknown = [newer, older];
    let statusCode = 200;
    const backend = createServer((request, reply) => {
      seen.push(`${request.method} ${request.url}`);
      reply.writeHead(statusCode, { "Content-Type": "application/json" });
      reply.end(JSON.stringify(response));
    });
    t.after(() => new Promise<void>((resolve, reject) => {
      backend.close(error => error ? reject(error) : resolve());
      backend.closeAllConnections();
    }));
    // Local test listener only. content-guard: allow infrastructure/localhost-bare
    backend.listen(0, "localhost");
    await once(backend, "listening");
    const address = backend.address();
    assert.ok(address && typeof address === "object");
    // Local stub backend only. content-guard: allow infrastructure/localhost-bare
    const env = { ...process.env, HOTWASH_URL: `http://localhost:${address.port}`,
      HOTWASH_API_KEY: "synthetic-upstream-key", HOTWASH_MCP_ALLOW_MUTATIONS: "false",
      // Local test MCP listener only. content-guard: allow infrastructure/localhost-bare
      HOTWASH_MCP_HTTP_TOKEN: randomUUID(), HOTWASH_MCP_HTTP_HOST: "localhost",
      HOTWASH_MCP_HTTP_PORT: "0" };
    const client = new Client({ name: "run-inventory-test", version: "1" });
    if (mode === "stdio") {
      const transport = new StdioClientTransport({ command: process.execPath,
        args: ["--import", "tsx", entry], env, stderr: "pipe" });
      t.after(() => client.close());
      await client.connect(transport);
    } else {
      const child = spawn(process.execPath, ["--import", "tsx", entry, "--http"], { env, stdio: ["ignore", "ignore", "pipe"] });
      t.after(async () => {
        await client.close();
        if (child.exitCode === null && child.signalCode === null) {
          const stopped = once(child, "exit");
          child.kill("SIGTERM");
          await stopped;
        }
      });
      const url = await new Promise<string>((resolve, reject) => {
        let diagnostics = "";
        child.once("error", reject);
        child.once("exit", () => reject(new Error("HTTP entry exited before listening")));
        child.stderr.on("data", chunk => {
          diagnostics += String(chunk);
          const match = diagnostics.match(/HTTP listening on (http:\/\/\S+\/mcp)/);
          if (match) resolve(match[1]);
        });
      });
      const transport = new StreamableHTTPClientTransport(new URL(url), {
        requestInit: { headers: { Authorization: `Bearer ${env.HOTWASH_MCP_HTTP_TOKEN}` } },
      });
      await client.connect(transport);
    }

    const tools = (await client.listTools()).tools;
    const registered = tools.filter(tool => tool.name === "hotwash_list_runs");
    assert.equal(registered.length, 1);
    assert.deepEqual(registered[0].annotations, {
      readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false,
    });
    assert.equal(tools.some(tool => tool.name === "hotwash_start_run"), false);
    const properties = registered[0].inputSchema.properties as Record<string, Record<string, unknown>>;
    assert.deepEqual(properties.status.enum, ["active", "paused", "completed", "abandoned"]);
    assert.equal(properties.limit.minimum, 1);
    assert.equal(properties.limit.maximum, 500);
    assert.equal(properties.limit.default, 50);
    assert.deepEqual(seen, []);

    const inventory = data(await client.callTool({ name: "hotwash_list_runs", arguments: {} }));
    assert.deepEqual(inventory.runs, [newer, older]);
    assert.equal(inventory.returned, 2);
    assert.equal(inventory.limit, 50);
    assert.deepEqual(seen.splice(0), ["GET /api/executions?limit=50"]);

    data(await client.callTool({ name: "hotwash_list_runs", arguments: { status: "active", limit: 5 } }));
    assert.deepEqual(seen.splice(0), ["GET /api/executions?status=active&limit=5"]);
    data(await client.callTool({ name: "hotwash_list_runs", arguments: { playbook_id: 7, limit: 500 } }));
    assert.deepEqual(seen.splice(0), ["GET /api/executions?playbook_id=7&limit=500"]);

    for (const args of [
      { status: "invalid" }, { status: "in_progress" }, { limit: 0 }, { limit: 501 },
      { limit: 1.5 }, { limit: "5" }, { playbook_id: 0 }, { playbook_id: 1.5 }, { offset: 1 },
    ]) {
      assert.equal((await client.callTool({ name: "hotwash_list_runs", arguments: args })).isError, true);
    }
    assert.deepEqual(seen, []);

    response = [];
    assert.deepEqual(data(await client.callTool({ name: "hotwash_list_runs", arguments: {} })).runs, []);
    response = { detail: "synthetic-backend-private-message" };
    statusCode = 503;
    const failed = await client.callTool({ name: "hotwash_list_runs", arguments: {} });
    assert.equal(failed.isError, true);
    assert.doesNotMatch(JSON.stringify(failed), /synthetic-backend-private-message/);
  });
}
