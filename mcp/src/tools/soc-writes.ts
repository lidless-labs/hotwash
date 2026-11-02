import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, guardMutation, mutatingTool, ok, type ToolPolicy } from "./_util.js";
import { id, observableFact, readPage } from "./soc.js";

// Bounded TheHive write tools for the SOC triage bot. Each tool is one fixed
// connector action. There is no update, delete, merge, close or share path.
// Every call needs the operator switch (HOTWASH_MCP_ALLOW_MUTATIONS) and
// `confirm: true`. Inputs are validated strictly before any backend request.

export const SOC_BOT_TAG = "soc-bot";
export const MAX_CASE_SEVERITY = 2;
export const MAX_MARKING = 2; // TLP:AMBER and PAP:AMBER
export const MAX_COMMENT_CHARS = 8000;
export const MAX_DESCRIPTION_CHARS = 8000;
export const MAX_TITLE_CHARS = 200;
export const MAX_USER_TAGS = 15; // plus the enforced soc-bot tag, 16 total
export const MAX_OBSERVABLE_MESSAGE_CHARS = 500;
export const MAX_PATH_CHARS = 1024;
// Pages of 100 checked when proving an observable is a hash in its case.
export const MAX_OBSERVABLE_LOOKUP_PAGES = 5;

const CONTROL = /[\x00-\x1f\x7f]/;
const noControl = (value: string) => !CONTROL.test(value);
// Free text may keep newlines and tabs but no other control character.
const noBinaryControl = (value: string) => !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value);

const confirm = z.literal(true).describe("Must be true. Acknowledges this call writes to TheHive.");
const marking = z.number().int().min(0).max(MAX_MARKING);
const tag = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}(?![\s\S])/);
const analyzerName = z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+(?![\s\S])/);

const createCaseInput = z.object({
  title: z.string().trim().min(1).max(MAX_TITLE_CHARS).refine(noControl, "control characters are not allowed"),
  description: z.string().trim().min(1).max(MAX_DESCRIPTION_CHARS).refine(noBinaryControl, "control characters are not allowed"),
  severity: z.number().int().min(1).max(MAX_CASE_SEVERITY).default(1)
    .describe("1 (low) or 2 (medium). Higher severities are refused."),
  tlp: marking.default(2).describe("0 to 2. TLP:AMBER (2) is the maximum."),
  pap: marking.default(2).describe("0 to 2. PAP:AMBER (2) is the maximum."),
  tags: z.array(tag).max(MAX_USER_TAGS).default([])
    .describe("Optional extra tags. The soc-bot tag is always added."),
  confirm,
}).strict();

const HASH = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})(?![\s\S])/;
const addObservableInput = z.object({
  case_id: id,
  dataType: z.enum(["hash", "filename"]).describe("hash: complete md5, sha1 or sha256 hex. filename: a file path, stored as data only."),
  value: z.string().min(1).max(MAX_PATH_CHARS),
  message: z.string().trim().min(1).max(MAX_OBSERVABLE_MESSAGE_CHARS).refine(noControl, "control characters are not allowed").optional(),
  tlp: marking.default(2).describe("0 to 2. TLP:AMBER (2) is the maximum."),
  ioc: z.boolean().default(false),
  confirm,
}).strict().superRefine((input, ctx) => {
  if (input.dataType === "hash") {
    if (!HASH.test(input.value)) {
      ctx.addIssue({ code: "custom", path: ["value"], message: "hash must be a complete md5 (32), sha1 (40) or sha256 (64) hex digest" });
    }
  } else if (!noControl(input.value) || input.value.trim() !== input.value) {
    ctx.addIssue({ code: "custom", path: ["value"], message: "file path must not contain control characters or edge whitespace" });
  }
});

const addCommentInput = z.object({
  case_id: id,
  message: z.string().trim().min(1).max(MAX_COMMENT_CHARS).refine(noBinaryControl, "control characters are not allowed"),
  confirm,
}).strict();

const runAnalyzerInput = z.object({
  case_id: id.describe("Case that contains the observable."),
  observable_id: id.describe("Hash observable in that case."),
  analyzer: analyzerName.describe("Analyzer id from the operator allowlist."),
  confirm,
}).strict();

const createdCase = z.object({
  case_id: id,
  number: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).nullish(),
});
const createdObservable = z.object({ observable_id: id });
const createdComment = z.object({ comment_id: id });
const launchedJob = z.object({
  job_id: id,
  status: z.string().min(1).max(64).nullish(),
});

// The case or object may exist even when the response is unusable, so say so
// instead of inviting a blind retry that would duplicate the write.
function unexpected(action: string): Error {
  return new Error(`Hotwash returned an unexpected ${action} response; the write may have happened, so check the case before retrying`);
}
function parseResult<T>(schema: z.ZodType<T>, source: unknown, action: string): T {
  const parsed = schema.safeParse(source);
  if (!parsed.success) throw unexpected(action);
  return parsed.data;
}

export function enforceSocBotTag(tags: string[]): string[] {
  return tags.includes(SOC_BOT_TAG) ? [...new Set(tags)] : [...new Set([...tags, SOC_BOT_TAG])];
}

const WRITE_TOOL = mutatingTool({ destructive: false, idempotent: false });

export function registerSocWriteTools(
  server: McpServer,
  client: HotwashClient,
  policy: ToolPolicy | undefined,
  analyzerAllowlist: readonly string[],
): void {
  const allowed = new Set(analyzerAllowlist);

  server.registerTool("hotwash_create_case", {
    description: `Create one TheHive triage case through the Hotwash connector. Requires HOTWASH_MCP_ALLOW_MUTATIONS=true on the server and confirm: true. Severity is 1 (default) or 2. TLP and PAP default to 2 (AMBER) and cannot exceed it. The tag ${SOC_BOT_TAG} is always added. Unknown fields are refused. Not idempotent: check hotwash_list_cases before creating, and do not retry a failed call blindly. Returns the case id and number.`,
    inputSchema: createCaseInput, annotations: WRITE_TOOL,
  }, async args => {
    const blocked = guardMutation(policy, "create this case");
    if (blocked) return blocked;
    try {
      const tags = enforceSocBotTag(args.tags);
      const created = parseResult(createdCase, await client.createCase({
        title: args.title, description: args.description, severity: args.severity,
        tlp: args.tlp, pap: args.pap, tags,
      }), "create_case");
      return ok({ case_id: created.case_id, number: created.number ?? null, severity: args.severity, tlp: args.tlp, pap: args.pap, tags });
    } catch (error) {
      return fail(error);
    }
  });

  server.registerTool("hotwash_add_case_observable", {
    description: "Add one observable to a known TheHive case: a complete md5, sha1 or sha256 hash (dataType hash) or a file path (dataType filename, data only, never opened). No other observable types. TLP defaults to 2 and cannot exceed 2. ioc defaults to false. Requires HOTWASH_MCP_ALLOW_MUTATIONS=true and confirm: true. Not idempotent. Returns the observable id.",
    inputSchema: addObservableInput, annotations: WRITE_TOOL,
  }, async args => {
    const blocked = guardMutation(policy, "add this observable");
    if (blocked) return blocked;
    try {
      const value = args.dataType === "hash" ? args.value.toLowerCase() : args.value;
      const created = parseResult(createdObservable, await client.addCaseObservable({
        case_id: args.case_id, data_type: args.dataType, data: value,
        ...(args.message === undefined ? {} : { message: args.message }),
        tlp: args.tlp, ioc: args.ioc,
      }), "add_observable");
      return ok({ observable_id: created.observable_id, case_id: args.case_id, dataType: args.dataType, tlp: args.tlp, ioc: args.ioc });
    } catch (error) {
      return fail(error);
    }
  });

  server.registerTool("hotwash_add_case_comment", {
    description: `Append one internal comment (1 to ${MAX_COMMENT_CHARS} characters) to a known TheHive case. The comment cannot be shared externally, edited or deleted through this tool. Requires HOTWASH_MCP_ALLOW_MUTATIONS=true and confirm: true. Not idempotent. Returns the comment id.`,
    inputSchema: addCommentInput, annotations: WRITE_TOOL,
  }, async args => {
    const blocked = guardMutation(policy, "add this comment");
    if (blocked) return blocked;
    try {
      const created = parseResult(createdComment, await client.addCaseComment({ case_id: args.case_id, message: args.message }), "add_comment");
      return ok({ comment_id: created.comment_id, case_id: args.case_id });
    } catch (error) {
      return fail(error);
    }
  });

  server.registerTool("hotwash_run_analyzer", {
    description: `Launch one allowlisted Cortex analyzer on a hash observable in a known case. The allowlist is operator configuration (HOTWASH_MCP_ANALYZER_ALLOWLIST, default CIRCLHashlookup_1_1 and MISP_2_1). The observable must belong to the case and be a hash. Requires HOTWASH_MCP_ALLOW_MUTATIONS=true and confirm: true. Launches only; it does not poll. Read the job with hotwash_get_analyzer_job. A launched job or a lookup miss is not a clean verdict. Returns the job id and status.`,
    inputSchema: runAnalyzerInput, annotations: WRITE_TOOL,
  }, async args => {
    const blocked = guardMutation(policy, "launch this analyzer");
    if (blocked) return blocked;
    if (!allowed.has(args.analyzer)) {
      // The allowlist is not echoed: it is operator configuration.
      return fail(new Error("Refusing to launch this analyzer: it is not on the operator allowlist."));
    }
    try {
      const kind = await findObservableKind(client, args.case_id, args.observable_id);
      if (kind === undefined) {
        return fail(new Error(`Refusing to launch: observable ${args.observable_id} was not found among the first ${MAX_OBSERVABLE_LOOKUP_PAGES * 100} hash or file-path observables of case ${args.case_id}.`));
      }
      if (kind !== "hash") {
        return fail(new Error("Refusing to launch: analyzers run only on hash observables."));
      }
    } catch {
      return fail(new Error("Refusing to launch: the observable could not be verified as a hash in this case."));
    }
    try {
      const job = parseResult(launchedJob, await client.runAnalyzer({ artifact_id: args.observable_id, analyzer_id: args.analyzer }), "run_analyzer");
      return ok(
        { job_id: job.job_id, status: job.status ?? null, analyzer: args.analyzer, observable_id: args.observable_id, case_id: args.case_id },
        ["status"],
      );
    } catch (error) {
      return fail(error);
    }
  });
}

// Reads the case's observables a bounded number of pages and returns the
// observable's type. The backend omits types it does not support, so absence
// means unsupported, missing or beyond the bound. All of those refuse.
async function findObservableKind(client: HotwashClient, caseId: string, observableId: string): Promise<"hash" | "filename" | undefined> {
  for (let index = 0; index < MAX_OBSERVABLE_LOOKUP_PAGES; index += 1) {
    const request = { offset: index * 100, limit: 100 };
    const result = readPage(await client.listCaseObservables(caseId, request), observableFact, request, caseId);
    const match = result.items.find(item => item.id === observableId);
    if (match) return match.data_type;
    if (!result.has_more) return undefined;
  }
  return undefined;
}
