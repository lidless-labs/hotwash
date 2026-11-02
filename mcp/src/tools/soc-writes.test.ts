import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { parseAnalyzerAllowlist } from "../config.js";
import type { HotwashConfig } from "../config.js";
import { createMcpServer } from "../server.js";

const realFetch = globalThis.fetch;
const connections: Client[] = [];
afterEach(async () => {
  globalThis.fetch = realFetch;
  await Promise.all(connections.splice(0).map(client => client.close()));
});
async function connect(config: Partial<HotwashConfig> = {}) {
  const server = createMcpServer({ url: "http://example.invalid", timeout: 1000, allowMutations: true, ...config });
  const client = new Client({ name: "soc-writes-test", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), client.connect(a)]);
  connections.push(client);
  return client;
}
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
interface Seen { method: string; path: string; body: unknown }
function record(handler: (seen: Seen) => Response | Promise<Response>) {
  const seen: Seen[] = [];
  globalThis.fetch = async (url, init) => {
    const entry = { method: init?.method ?? "GET", path: new URL(String(url)).pathname,
      body: init?.body ? JSON.parse(String(init.body)) : undefined };
    seen.push(entry);
    return handler(entry);
  };
  return seen;
}
const data = (result: unknown) => (result as { structuredContent: Record<string, unknown> }).structuredContent;
const HASH = "a".repeat(64);
const WRITES = "/api/integrations/thehive/actions/";

const validCalls: [string, Record<string, unknown>][] = [
  ["hotwash_create_case", { title: "t", description: "d", confirm: true }],
  ["hotwash_add_case_observable", { case_id: "~C1", dataType: "hash", value: HASH, confirm: true }],
  ["hotwash_add_case_comment", { case_id: "~C1", message: "note", confirm: true }],
  ["hotwash_run_analyzer", { case_id: "~C1", observable_id: "~O1", analyzer: "MISP_2_1", confirm: true }],
];

// --- gates -----------------------------------------------------------------

for (const [name, args] of validCalls) {
  test(`${name} is refused unless the operator enabled mutations`, async () => {
    const seen = record(() => json({}));
    const client = await connect({ allowMutations: false });
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true);
    assert.match(JSON.stringify(result.content), /HOTWASH_MCP_ALLOW_MUTATIONS/);
    assert.equal(seen.length, 0, "no backend request may be made");
  });

  test(`${name} needs confirm: true and rejects unknown fields before any request`, async () => {
    const seen = record(() => json({}));
    const client = await connect();
    const { confirm: _confirm, ...withoutConfirm } = args;
    for (const bad of [withoutConfirm, { ...args, confirm: false }, { ...args, confirm: "true" },
      { ...args, status: "Closed" }, { ...args, url: "http://other.invalid" }]) {
      assert.equal((await client.callTool({ name, arguments: bad })).isError, true, JSON.stringify(bad));
    }
    assert.equal(seen.length, 0);
  });
}

test("the four tools declare non-read-only, non-destructive, closed-world hints", async () => {
  const client = await connect();
  const tools = new Map((await client.listTools()).tools.map(tool => [tool.name, tool.annotations]));
  for (const [name] of validCalls) {
    assert.deepEqual(tools.get(name), { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false }, name);
  }
  for (const banned of ["delete", "update", "merge", "close", "share"]) {
    assert.equal([...tools.keys()].some(name => /case|observable|comment|analyzer/.test(name) && name.includes(banned)), false, banned);
  }
});

// --- hotwash_create_case ------------------------------------------------------------

test("create_case applies safe defaults, adds soc-bot and returns only id and number", async () => {
  const seen = record(() => json({ case_id: "~C9", number: 42, url: "https://thehive.invalid/cases/42/details",
    raw: { _id: "~C9", secret: "apikey=hunter2", owner: "someone" } }));
  const client = await connect();
  const result = await client.callTool({ name: "hotwash_create_case", arguments: { title: "  Suspicious binary ", description: "Rootcheck hit", confirm: true } });
  assert.notEqual(result.isError, true);
  assert.deepEqual(seen.map(s => [s.method, s.path]), [["POST", `${WRITES}create_case`]]);
  assert.deepEqual(seen[0].body, { title: "Suspicious binary", description: "Rootcheck hit", severity: 1, tlp: 2, pap: 2, tags: ["soc-bot"] });
  assert.deepEqual(data(result), { case_id: "~C9", number: 42, severity: 1, tlp: 2, pap: 2, tags: ["soc-bot"] });
  assert.doesNotMatch(JSON.stringify(result), /hunter2|thehive.invalid|someone/);
});

test("create_case keeps user tags, never duplicates soc-bot and always includes it", async () => {
  const seen = record(() => json({ case_id: "~C9", number: 1 }));
  const client = await connect();
  await client.callTool({ name: "hotwash_create_case", arguments: { title: "t", description: "d", tags: ["wazuh", "soc-bot", "wazuh"], severity: 2, tlp: 1, pap: 0, confirm: true } });
  await client.callTool({ name: "hotwash_create_case", arguments: { title: "t", description: "d", tags: ["wazuh"], confirm: true } });
  assert.deepEqual((seen[0].body as { tags: string[] }).tags, ["wazuh", "soc-bot"]);
  assert.deepEqual((seen[1].body as { tags: string[] }).tags, ["wazuh", "soc-bot"]);
  assert.equal((seen[0].body as { severity: number }).severity, 2);
  assert.equal((seen[0].body as { pap: number }).pap, 0);
});

test("create_case enforces severity, TLP, PAP, tag and text bounds before HTTP", async () => {
  const seen = record(() => json({ case_id: "~C9", number: 1 }));
  const client = await connect();
  const base = { title: "t", description: "d", confirm: true };
  const tooMany = Array.from({ length: 16 }, (_, i) => `t${i}`);
  for (const bad of [
    { severity: 3 }, { severity: 0 }, { severity: 1.5 }, { tlp: 3 }, { tlp: -1 }, { pap: 3 },
    { tags: ["bad tag"] }, { tags: ["x".repeat(129)] }, { tags: tooMany }, { tags: [""] },
    { title: "" }, { title: "   " }, { title: "x".repeat(201) }, { title: "a\nb" },
    { description: "" }, { description: "x".repeat(8001) }, { description: "a\u0000b" },
  ]) {
    const result = await client.callTool({ name: "hotwash_create_case", arguments: { ...base, ...bad } });
    assert.equal(result.isError, true, JSON.stringify(bad).slice(0, 80));
  }
  assert.equal(seen.length, 0);
  const associationTags = ["hotwash:finding:v1:" + "a".repeat(64), "hotwash:rootcheck:v2:group:" + "b".repeat(64), "hotwash:rootcheck:v2:path:" + "c".repeat(64)];
  assert.notEqual((await client.callTool({ name: "hotwash_create_case", arguments: { ...base, tags: associationTags } })).isError, true, "association tags");
  assert.deepEqual((seen.at(-1)!.body as { tags: string[] }).tags, [...associationTags, "soc-bot"]);
  for (const good of [{ severity: 2, tlp: 2, pap: 2 }, { title: "x".repeat(200) }, { description: "x".repeat(8000) }, { tags: tooMany.slice(0, 15) }]) {
    assert.notEqual((await client.callTool({ name: "hotwash_create_case", arguments: { ...base, ...good } })).isError, true, JSON.stringify(good).slice(0, 80));
  }
  assert.equal((seen.at(-1)!.body as { tags: string[] }).tags.length, 16);
});

// --- hotwash_add_case_observable -----------------------------------------------------

test("add_case_observable accepts only complete hashes and file paths", async () => {
  const seen = record(() => json({ observable_id: "~O5", raw: { token: "secret" } }));
  const client = await connect();
  for (const value of ["d".repeat(32), "e".repeat(40), HASH.toUpperCase()]) {
    const result = await client.callTool({ name: "hotwash_add_case_observable", arguments: { case_id: "~C1", dataType: "hash", value, confirm: true } });
    assert.notEqual(result.isError, true, value);
    assert.deepEqual(data(result), { observable_id: "~O5", case_id: "~C1", dataType: "hash", tlp: 2, ioc: false });
  }
  assert.deepEqual(seen.map(s => (s.body as { data: string }).data), ["d".repeat(32), "e".repeat(40), HASH]);
  assert.deepEqual(seen[0].body, { case_id: "~C1", data_type: "hash", data: "d".repeat(32), tlp: 2, ioc: false });
  assert.equal(seen[0].path, `${WRITES}add_observable`);

  const path = await client.callTool({ name: "hotwash_add_case_observable",
    arguments: { case_id: "~C1", dataType: "filename", value: "/tmp/dropper.bin", message: "seen in rootcheck", tlp: 1, ioc: true, confirm: true } });
  assert.notEqual(path.isError, true);
  assert.deepEqual(seen[3].body, { case_id: "~C1", data_type: "filename", data: "/tmp/dropper.bin", message: "seen in rootcheck", tlp: 1, ioc: true });
  assert.doesNotMatch(JSON.stringify(path), /secret/);
});

test("add_case_observable rejects other types, partial hashes, bad paths and high TLP before HTTP", async () => {
  const seen = record(() => json({ observable_id: "~O5" }));
  const client = await connect();
  const base = { case_id: "~C1", confirm: true };
  for (const bad of [
    { dataType: "ip", value: "192.0.2.1" }, { dataType: "domain", value: "example.com" },
    { dataType: "url", value: "http://example.com" }, { dataType: "file", value: "/tmp/x" },
    { dataType: "hash", value: "a".repeat(31) }, { dataType: "hash", value: "a".repeat(41) },
    { dataType: "hash", value: "a".repeat(63) }, { dataType: "hash", value: "a".repeat(65) },
    { dataType: "hash", value: "a".repeat(128) }, { dataType: "hash", value: "g".repeat(64) },
    { dataType: "hash", value: HASH + "\n" }, { dataType: "hash", value: "short" },
    { dataType: "filename", value: "" }, { dataType: "filename", value: "/tmp/a\nb" },
    { dataType: "filename", value: "/tmp/a\u0000b" }, { dataType: "filename", value: " /tmp/a" },
    { dataType: "filename", value: "x".repeat(1025) },
    { dataType: "hash", value: HASH, tlp: 3 }, { dataType: "hash", value: HASH, tlp: -1 },
    { dataType: "hash", value: HASH, ioc: "yes" }, { dataType: "hash", value: HASH, message: "x".repeat(501) },
    { dataType: "hash", value: HASH, tags: ["x"] }, { dataType: "hash", value: HASH, sighted: true },
    { dataType: "hash", value: HASH, case_id: "~1/../x" }, { dataType: "hash", value: HASH, case_id: "~1\n" },
  ]) {
    assert.equal((await client.callTool({ name: "hotwash_add_case_observable", arguments: { ...base, ...bad } })).isError, true, JSON.stringify(bad));
  }
  assert.equal(seen.length, 0);
});

// --- hotwash_add_case_comment --------------------------------------------------------

test("add_case_comment posts a bounded internal comment and returns only ids", async () => {
  const seen = record(() => json({ comment_id: "~M3", raw: { createdBy: "svc-account" } }));
  const client = await connect();
  const result = await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message: "line one\nline two", confirm: true } });
  assert.notEqual(result.isError, true);
  assert.deepEqual(seen[0].body, { case_id: "~C1", message: "line one\nline two" });
  assert.equal(seen[0].path, `${WRITES}add_comment`);
  assert.deepEqual(data(result), { comment_id: "~M3", case_id: "~C1" });
  const max = await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message: "x".repeat(8000), confirm: true } });
  assert.notEqual(max.isError, true);
  seen.length = 0;
  for (const message of ["", "   ", "x".repeat(8001), "a\u0000b"]) {
    assert.equal((await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message, confirm: true } })).isError, true);
  }
  for (const case_id of ["C1", "~C1/x", "~" + "a".repeat(128), "~C1\n"]) {
    assert.equal((await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id, message: "ok", confirm: true } })).isError, true, case_id);
  }
  assert.equal(seen.length, 0);
});

// --- hotwash_run_analyzer ------------------------------------------------------------

const observablePage = (items: unknown[], extra: Record<string, unknown> = {}) => ({
  items, returned: items.length, scanned: items.length, offset: 0, limit: 100, has_more: false, overflow: false,
  observed_at: "2026-01-01T00:00:00Z", coverage: "unverified", gaps: ["query_contract_unverified"], case_id: "~C1", ...extra,
});
const hashFact = (id: string) => ({ id, data_type: "hash", data: HASH, tlp: 2, dates: {} });
const fileFact = (id: string) => ({ id, data_type: "filename", data: "/tmp/x", tlp: 2, dates: {} });
const runArgs = (extra: Record<string, unknown> = {}) => ({ case_id: "~C1", observable_id: "~O1", analyzer: "MISP_2_1", confirm: true, ...extra });

test("run_analyzer launches an allowlisted analyzer on a verified hash and returns the job id", async () => {
  const seen = record(entry => entry.method === "GET"
    ? json(observablePage([fileFact("~O0"), hashFact("~O1")]))
    : json({ job_id: "~J1", status: "Waiting", raw: { apiKey: "secret" } }));
  const client = await connect();
  for (const analyzer of ["CIRCLHashlookup_1_1", "MISP_2_1"]) {
    const result = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs({ analyzer }) });
    assert.notEqual(result.isError, true, analyzer);
    assert.deepEqual(data(result).job_id, "~J1");
    assert.equal(data(result).status, "Waiting");
    assert.doesNotMatch(JSON.stringify(result), /secret/);
  }
  const posts = seen.filter(s => s.method === "POST");
  assert.equal(posts.length, 2);
  assert.equal(posts[0].path, `${WRITES}run_analyzer`);
  assert.deepEqual(posts[0].body, { artifact_id: "~O1", analyzer_id: "CIRCLHashlookup_1_1" });
  assert.deepEqual(seen[0].path, "/api/integrations/thehive/cases/~C1/observables");
});

test("run_analyzer refuses analyzers outside the allowlist before any request", async () => {
  const seen = record(() => json({}));
  const client = await connect();
  for (const analyzer of ["Abuse_Finder_3_0", "misp_2_1", "MISP_2_1 ", "MISP_2_1,CIRCLHashlookup_1_1", "*", "../x", "", "MISP_2_2"]) {
    const result = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs({ analyzer }) });
    assert.equal(result.isError, true, analyzer);
  }
  assert.equal(seen.length, 0);
  const refusal = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs({ analyzer: "Abuse_Finder_3_0" }) });
  assert.match(JSON.stringify(refusal.content), /allowlist/);
  assert.doesNotMatch(JSON.stringify(refusal.content), /CIRCLHashlookup|MISP_2_1/);
});

test("run_analyzer allowlist is operator configuration, replacing the default", async () => {
  const seen = record(entry => entry.method === "GET" ? json(observablePage([hashFact("~O1")])) : json({ job_id: "~J2" }));
  const client = await connect({ analyzerAllowlist: ["Custom_Analyzer_1_0"] });
  assert.equal((await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs({ analyzer: "MISP_2_1" }) })).isError, true);
  assert.equal(seen.length, 0);
  const result = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs({ analyzer: "Custom_Analyzer_1_0" }) });
  assert.notEqual(result.isError, true);
  assert.equal(data(result).status, null);
  const closed = await connect({ analyzerAllowlist: [] });
  assert.equal((await closed.callTool({ name: "hotwash_run_analyzer", arguments: runArgs() })).isError, true);
});

test("analyzer allowlist environment parsing is exact and fails closed", () => {
  assert.deepEqual(parseAnalyzerAllowlist(undefined), ["CIRCLHashlookup_1_1", "MISP_2_1"]);
  assert.deepEqual(parseAnalyzerAllowlist("  "), ["CIRCLHashlookup_1_1", "MISP_2_1"]);
  assert.deepEqual(parseAnalyzerAllowlist("A_1, B-2 ,A_1"), ["A_1", "B-2"]);
  assert.deepEqual(parseAnalyzerAllowlist("bad id,../x,*,a;b"), []);
});

test("run_analyzer launches only on hash observables that belong to the case", async () => {
  const seen = record(entry => entry.method === "GET" ? json(observablePage([fileFact("~O1"), hashFact("~O2")])) : json({ job_id: "~J3" }));
  const client = await connect();
  const file = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs({ observable_id: "~O1" }) });
  assert.equal(file.isError, true);
  assert.match(JSON.stringify(file.content), /only on hash/);
  const missing = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs({ observable_id: "~Other" }) });
  assert.equal(missing.isError, true);
  assert.match(JSON.stringify(missing.content), /not found/);
  assert.equal(seen.some(s => s.method === "POST"), false);
});

const fullFilePage = (offset: number) => observablePage(
  Array.from({ length: 100 }, (_, i) => fileFact(`~F${offset}x${i}`)),
  { has_more: true, overflow: true, scanned: 100, returned: 100, offset });

test("run_analyzer bounds the observable lookup to five pages and fails closed", async () => {
  const urls: string[] = [];
  globalThis.fetch = async (url, init) => {
    urls.push(`${init?.method ?? "GET"} ${new URL(String(url)).search}`);
    return json(fullFilePage(Number(new URL(String(url)).searchParams.get("offset"))));
  };
  const client = await connect();
  const result = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs() });
  assert.equal(result.isError, true);
  assert.deepEqual(urls, [0, 100, 200, 300, 400].map(offset => `GET ?offset=${offset}&limit=100`));
});

test("run_analyzer does not launch when the observable read is malformed", async () => {
  const urls: string[] = [];
  globalThis.fetch = async (url, init) => { urls.push(`${init?.method ?? "GET"} ${new URL(String(url)).pathname}`); return json({ wrong: "shape" }); };
  const client = await connect();
  const result = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs() });
  assert.equal(result.isError, true);
  assert.deepEqual(urls, ["GET /api/integrations/thehive/cases/~C1/observables"]);
});

test("run_analyzer finds a hash on a later page", async () => {
  const urls: string[] = [];
  globalThis.fetch = async (url, init) => {
    urls.push(`${init?.method ?? "GET"} ${new URL(String(url)).search}`);
    if (init?.method === "POST") return json({ job_id: "~J5", status: "Waiting" });
    const offset = Number(new URL(String(url)).searchParams.get("offset"));
    return offset === 0 ? json(fullFilePage(0)) : json(observablePage([hashFact("~O1")], { offset }));
  };
  const client = await connect();
  const result = await client.callTool({ name: "hotwash_run_analyzer", arguments: runArgs() });
  assert.notEqual(result.isError, true);
  assert.deepEqual(urls, ["GET ?offset=0&limit=100", "GET ?offset=100&limit=100", "POST "]);
});

// --- failure handling ----------------------------------------------------------------

test("write failures expose no backend text, are never retried or redirected", async () => {
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return json({ detail: "token=hunter2 at https://private.invalid" }, 502); };
  const client = await connect({ apiKey: "key-123" });
  const failed = await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message: "m", confirm: true } });
  assert.equal(failed.isError, true);
  assert.match(JSON.stringify(failed.content), /HTTP 502/);
  assert.doesNotMatch(JSON.stringify(failed), /hunter2|private.invalid|key-123/);
  assert.equal(calls, 1);

  calls = 0;
  globalThis.fetch = async (_url, init) => {
    calls += 1;
    assert.equal(init?.redirect, "manual");
    return new Response(null, { status: 307, headers: { Location: "/elsewhere" } });
  };
  assert.equal((await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message: "m", confirm: true } })).isError, true);
  assert.equal(calls, 1, "a write is never re-sent to a redirect target");

  globalThis.fetch = async () => { throw new Error("connect ECONNREFUSED 192.0.2.9:8000 key-123"); };
  const network = await client.callTool({ name: "hotwash_create_case", arguments: { title: "t", description: "d", confirm: true } });
  assert.equal(network.isError, true);
  assert.doesNotMatch(JSON.stringify(network), /192\.0\.2\.9|key-123|ECONNREFUSED/);
  assert.match(JSON.stringify(network.content), /outcome not confirmed/);
});

test("unexpected success bodies are reported without echoing them", async () => {
  record(() => json({ case_id: "~C1/../x", number: 1, raw: { secret: "s3cret" } }));
  const client = await connect();
  const result = await client.callTool({ name: "hotwash_create_case", arguments: { title: "t", description: "d", confirm: true } });
  assert.equal(result.isError, true);
  assert.match(JSON.stringify(result.content), /may have happened/);
  assert.doesNotMatch(JSON.stringify(result), /s3cret|\.\.\/x/);
  record(() => new Response("not json", { status: 200 }));
  assert.equal((await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message: "m", confirm: true } })).isError, true);
});

test("oversized backend responses are cut off", async () => {
  globalThis.fetch = async () => new Response("x".repeat(2000), { status: 200 });
  const client = await connect({ maxResponseBytes: 100 });
  const result = await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message: "m", confirm: true } });
  assert.equal(result.isError, true);
});

test("write requests send the API key header only to the configured backend", async () => {
  let headers: Record<string, string> = {};
  globalThis.fetch = async (_url, init) => { headers = init?.headers as Record<string, string>; return json({ comment_id: "~M1" }); };
  const client = await connect({ apiKey: "key-123" });
  await client.callTool({ name: "hotwash_add_case_comment", arguments: { case_id: "~C1", message: "m", confirm: true } });
  assert.equal(headers["X-API-Key"], "key-123");
  assert.equal(headers["Content-Type"], "application/json");
});
