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
    tool(_name: string, _description: string, shape: z.ZodRawShape, _annotations: unknown, callback: typeof handler) {
      schema = z.object(shape);
      handler = callback;
    },
  } as unknown as McpServer;
  const client = new HotwashClient({ url: "http://example.invalid", timeout: 30000 });
  registerArtifactTools(server, client, { allowMutations: true });
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

const LIMIT = 25 * 1024 * 1024;

function artifactHarness() {
  let schema!: z.ZodObject<z.ZodRawShape>;
  let handler!: (args: Record<string, unknown>) => Promise<unknown>;
  const received: Uint8Array[] = [];
  const server = {
    tool(_name: string, _description: string, shape: z.ZodRawShape, _annotations: unknown, callback: typeof handler) {
      schema = z.object(shape);
      handler = callback;
    },
  } as unknown as McpServer;
  const client = { async attachArtifact(_run: number, _node: string, _name: string, bytes: Uint8Array) {
    received.push(bytes);
    return { node_id: 'collect', evidence: [] };
  } } as unknown as HotwashClient;
  registerArtifactTools(server, client, { allowMutations: true });
  return { schema, handler, received };
}

const artifactInput = { execution_id: 1, node_id: 'collect', filename: 'synthetic.bin' };

test('artifact schema bounds encoded strings', () => {
  const { schema } = artifactHarness();
  assert.equal(schema.safeParse({ ...artifactInput, text: 'a'.repeat(LIMIT + 1) }).success, false);
  assert.equal(schema.safeParse({ ...artifactInput, base64: 'A'.repeat(4 * Math.ceil(LIMIT / 3) + 1) }).success, false);
});

test('artifact rejects invalid or oversized payloads before allocating a buffer or calling the client', async () => {
  const { handler, received } = artifactHarness();
  const inputs = [
    { text: 'a'.repeat(LIMIT + 1) },
    { text: 'é'.repeat(LIMIT / 2) + 'a' },
    { text: '😀'.repeat(LIMIT / 4) + 'a' },
    { base64: Buffer.alloc(LIMIT + 1).toString('base64') },
    ...['!!!!', 'YQ=', 'A', 'YQ===', 'Y Q==', 'YQ==junk', 'YR=='].map(base64 => ({ base64 })),
  ];
  for (const input of inputs) {
    const original = Buffer.from;
    let allocations = 0;
    try {
      Buffer.from = ((...args: Parameters<typeof Buffer.from>) => {
        allocations++;
        return original(...args);
      }) as typeof Buffer.from;
      const result = await handler({ ...artifactInput, ...input });
      assert.equal((result as { isError?: boolean }).isError, true, JSON.stringify(input).slice(0, 80));
      assert.equal(allocations, 0);
    } finally {
      Buffer.from = original;
    }
  }
  assert.equal(received.length, 0);
});

test('artifact accepts exact byte boundaries and ordinary binary and UTF-8 content', async () => {
  const { schema, handler, received } = artifactHarness();
  for (const text of ['a'.repeat(LIMIT), 'é'.repeat(LIMIT / 2), '😀'.repeat(LIMIT / 4), 'incident log']) {
    const result = await handler(schema.parse({ ...artifactInput, text }));
    assert.notEqual((result as { isError?: boolean }).isError, true);
    assert.equal(Buffer.from(received.pop()!).toString('utf8'), text);
  }
  for (const bytes of [Buffer.alloc(LIMIT, 0xab), Buffer.from([0, 255, 128, 1])]) {
    const result = await handler(schema.parse({ ...artifactInput, base64: bytes.toString('base64') }));
    assert.notEqual((result as { isError?: boolean }).isError, true);
    assert.deepEqual(Buffer.from(received.pop()!), bytes);
  }
});

test("artifact rejects ambiguous empty content selectors", async () => {
  const { handler, received } = artifactHarness();
  for (const input of [
    { text: "", base64: "YQ==" },
    { text: "a", base64: "" },
  ]) {
    const result = await handler({ ...artifactInput, ...input });
    assert.equal((result as { isError?: boolean }).isError, true);
  }
  assert.equal(received.length, 0);
});
