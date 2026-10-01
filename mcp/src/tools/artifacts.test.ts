import assert from "node:assert/strict";
import { test } from "node:test";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { HotwashClient } from "../client.js";
import { registerArtifactTools } from "./artifacts.js";

test("artifact tool validates and sends provenance through client multipart", async () => {
  let schema: z.ZodObject<z.ZodRawShape> | undefined;
  let handler: ((args: Record<string, unknown>) => Promise<unknown>) | undefined;
  const server = {
    tool(_name: string, _description: string, shape: z.ZodRawShape, callback: typeof handler) {
      schema = z.object(shape);
      handler = callback;
    },
  } as unknown as McpServer;
  const client = new HotwashClient({ url: "http://example.invalid", timeout: 30000 });
  registerArtifactTools(server, client);
  assert.ok(schema);
  assert.ok(handler);
  const input = { execution_id: 42, node_id: "collect", filename: "ioc.txt", text: "example bytes",
    source_tool: "zeek", source_ref: "opaque-ref", observed_at: "2026-09-29T12:00:00+02:00" };
  assert.equal(schema.safeParse({ ...input, observed_at: "2026-09-29" }).success, false);
  assert.equal(schema.safeParse({ ...input, source_tool: "" }).success, false);
  assert.equal(schema.safeParse({ ...input, observed_at: "2026-09-29T12:00:00+00:99" }).success, false);
  assert.equal(schema.safeParse({ ...input, observed_at: "2026-09-29T12:00:00+24:00" }).success, false);
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init) => {
      assert.equal(url, "http://example.invalid/api/executions/42/steps/collect/evidence");
      assert.equal(init?.method, "POST");
      const form = init?.body as FormData;
      assert.ok(form instanceof FormData);
      assert.equal(form.get("source_tool"), input.source_tool);
      assert.equal(form.get("source_ref"), input.source_ref);
      assert.equal(form.get("observed_at"), input.observed_at);
      const file = form.get("file") as File;
      assert.equal(file.name, "ioc.txt");
      assert.equal(await file.text(), "example bytes");
      return new Response(JSON.stringify({ node_id: "collect", evidence: [{ ...input }] }), {
        status: 200, headers: { "Content-Type": "application/json" },
      });
    };
    const result = await handler(schema.parse(input));
    assert.match(JSON.stringify(result), /opaque-ref/);
  } finally {
    globalThis.fetch = previous;
  }
});
