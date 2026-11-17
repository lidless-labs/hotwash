import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../server.js";

const realFetch = globalThis.fetch;
const connections: Client[] = [];
afterEach(async () => {
  globalThis.fetch = realFetch;
  await Promise.all(connections.splice(0).map(client => client.close()));
});
async function connect(allowMutations = true) {
  const server = createMcpServer({ url: "https://example.invalid", timeout: 1000, allowMutations });
  const client = new Client({ name: "playbook-write-test", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), client.connect(a)]);
  connections.push(client);
  return client;
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
interface Seen { method: string; path: string; body: unknown; redirect: unknown }
function record(handler: (entry: Seen) => Response) {
  const seen: Seen[] = [];
  globalThis.fetch = async (url, init) => {
    const entry = { method: init?.method ?? "GET", path: new URL(String(url)).pathname,
      body: init?.body ? JSON.parse(String(init.body)) : undefined, redirect: init?.redirect };
    seen.push(entry);
    return handler(entry);
  };
  return seen;
}
const create = { title: "Triage", description: "Review alert", category: "SOC", tags: ["triage"], content_markdown: "# Triage\n\n## Review\n\tCheck evidence\r\n", confirm: true };
const update = { playbook_id: 7, title: "Revised", confirm: true };
const owned = { id: 7, tags: [{ id: 1, name: "soc-bot" }, { id: 2, name: "draft" }] };
const calls: [string, Record<string, unknown>][] = [["hotwash_create_playbook", create], ["hotwash_update_playbook", update]];
for (const [name, args] of calls) {
  test(`${name} refuses disabled mutations before any read or write`, async () => {
    const seen = record(() => json(owned));
    const client = await connect(false);
    assert.equal((await client.callTool({ name, arguments: args })).isError, true);
    assert.equal(seen.length, 0);
  });
  test(`${name} requires literal confirmation and strict fields`, async () => {
    const seen = record(() => json(owned));
    const client = await connect();
    const { confirm: _, ...unconfirmed } = args;
    for (const bad of [unconfirmed, { ...args, confirm: false }, { ...args, confirm: "true" }, { ...args, graph_json: {} }, { ...args, url: "https://other.invalid" }]) {
      assert.equal((await client.callTool({ name, arguments: bad })).isError, true);
    }
    assert.equal(seen.length, 0);
  });
  test(`${name} rejects oversized strings, tags and controls before requests`, async () => {
    const seen = record(() => json(owned));
    const client = await connect();
    for (const [field, max] of [["title", 200], ["description", 8000], ["category", 100], ["content_markdown", 100000]] as const) {
      for (const value of ["x".repeat(max + 1), "bad\u0000", "bad\u007f", "bad\u0085"]) {
        assert.equal((await client.callTool({ name, arguments: { ...args, [field]: value } })).isError, true, field);
      }
    }
    for (const tags of [["x".repeat(101)], Array(19).fill("a"), ["bad\n"], ["\u0000"]]) {
      assert.equal((await client.callTool({ name, arguments: { ...args, tags } })).isError, true);
    }
    assert.equal(seen.length, 0);
  });
}
test("create posts the REST shape with deduplicated mandatory draft and ownership tags", async () => {
  const seen = record(() => json({ ...owned, secret: "do-not-echo" }, 201));
  const client = await connect();
  const result = await client.callTool({ name: calls[0][0], arguments: { ...create, tags: ["triage", " SOC BOT ", "soc-bot", "triage"] } });
  assert.notEqual(result.isError, true);
  assert.deepEqual(seen, [{ method: "POST", path: "/api/playbooks", redirect: "manual", body: {
    title: create.title, description: create.description, category: create.category,
    content_markdown: create.content_markdown, tags: ["triage", "soc-bot", "draft"],
  } }]);
  assert.doesNotMatch(JSON.stringify(result), /do-not-echo/);
});
test("update merges tags and never drops existing draft or human tags", async () => {
  const human = { id: 7, tags: [{ id: 1, name: "soc-bot" }, { id: 2, name: "draft" }, { id: 3, name: "reviewed-by-solomon" }] };
  const seen = record(() => json(human));
  const client = await connect();
  const result = await client.callTool({ name: "hotwash_update_playbook", arguments: { playbook_id: 7, tags: ["triage"], confirm: true } });
  assert.notEqual(result.isError, true);
  assert.deepEqual((seen[1].body as { tags: string[] }).tags, ["soc-bot", "draft", "reviewed-by-solomon", "triage"]);
});

test("update refuses human playbooks, missing tags, mismatched ids and failed lookups", async () => {
  const client = await connect();
  for (const response of [{ id: 7, tags: [{ name: "human" }] }, { id: 7 }, { ...owned, id: 8 }, null]) {
    const seen = record(() => json(response));
    assert.equal((await client.callTool({ name: calls[1][0], arguments: update })).isError, true);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].method, "GET");
  }
  const seen = record(() => json({ detail: "secret" }, 404));
  const result = await client.callTool({ name: calls[1][0], arguments: update });
  assert.equal(result.isError, true);
  assert.equal(seen.length, 1);
  assert.doesNotMatch(JSON.stringify(result), /secret/);
});
test("update fetches first, preserves omitted fields, and forces soc-bot on tag replacement", async () => {
  const client = await connect();
  for (const extra of [{}, { tags: [] }, { tags: ["reviewed", "soc-bot", "reviewed"] }]) {
    const seen = record(() => json(owned));
    assert.notEqual((await client.callTool({ name: calls[1][0], arguments: { ...update, ...extra } })).isError, true);
    assert.deepEqual(seen.map(s => [s.method, s.path]), [["GET", "/api/playbooks/7"], ["PUT", "/api/playbooks/7"]]);
    assert.deepEqual(seen[1].body, { title: "Revised", ...(extra.tags !== undefined ? { tags: extra.tags.length ? ["soc-bot", "draft", "reviewed"] : ["soc-bot", "draft"] } : {}) });
    assert.equal(seen[1].redirect, "manual");
  }
});
test("update rejects empty patches and unsafe ids", async () => {
  const seen = record(() => json(owned));
  const client = await connect();
  for (const args of [{ playbook_id: 7, confirm: true }, ...[0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1].map(playbook_id => ({ ...update, playbook_id }))]) {
    assert.equal((await client.callTool({ name: calls[1][0], arguments: args })).isError, true);
  }
  assert.equal(seen.length, 0);
});
test("write failures and redirects are not retried and expose no backend detail", async () => {
  const client = await connect();
  for (const status of [302, 400, 500]) {
    const seen = record(() => json({ detail: "private-response" }, status));
    const result = await client.callTool({ name: calls[0][0], arguments: create });
    assert.equal(result.isError, true);
    assert.doesNotMatch(JSON.stringify(result), /private-response/);
    assert.equal(seen.length, 1);
  }
});

test("valid boundary sizes are accepted and metadata controls are refused", async () => {
  const client = await connect();
  const seen = record(() => json(owned));
  const result = await client.callTool({ name: calls[0][0], arguments: {
    title: "t".repeat(200), description: "d".repeat(8000), category: "c".repeat(100),
    content_markdown: "m".repeat(100000), tags: Array.from({ length: 18 }, (_, i) => String(i).padEnd(100, "t")), confirm: true,
  } });
  assert.notEqual(result.isError, true);
  assert.equal(seen.length, 1);
  for (const field of ["title", "category"]) {
    assert.equal((await client.callTool({ name: calls[0][0], arguments: { ...create, [field]: "bad\nline" } })).isError, true);
  }
  assert.equal(seen.length, 1);
});
