import { guardMutation, mutatingTool, type ToolPolicy } from "./_util.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, ok, READ_ONLY_TOOL } from "./_util.js";

export function registerPlaybookTools(server: McpServer, client: HotwashClient): void {
  server.tool(
    "hotwash_list_playbooks",
    "List playbooks in the Hotwash library. Optional filters by category, tag, or search string. Returns id, title, category, tag list, and node count for each match.",
    {
      category: z.string().optional().describe("Filter by category, e.g. 'Incident Response', 'Vulnerability', 'Threat Hunting'."),
      tag: z.string().optional().describe("Filter by tag name."),
      search: z.string().optional().describe("Free-text search across title and description."),
    },
    READ_ONLY_TOOL,
    async ({ category, tag, search }) => {
      try {
        const playbooks = await client.listPlaybooks({ category, tag, search });
        return ok(
          {
            count: playbooks.length,
            playbooks: playbooks.map((p) => ({
              id: p.id,
              title: p.title,
              category: p.category ?? null,
              tags: (p.tags ?? []).map((t) => t.name),
              node_count: p.node_count ?? 0,
              description: p.description ?? null,
            })),
          },
          ["playbooks[].title", "playbooks[].category", "playbooks[].tags", "playbooks[].description"],
        );
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "hotwash_get_playbook",
    "Fetch the full graph (nodes + edges) and metadata for a single playbook by id. Use this before starting a run to inspect what steps and decisions the playbook contains.",
    {
      playbook_id: z.number().int().positive().describe("Numeric playbook id from list_playbooks."),
    },
    READ_ONLY_TOOL,
    async ({ playbook_id }) => {
      try {
        const playbook = await client.getPlaybook(playbook_id);
        return ok(
          {
            id: playbook.id,
            title: playbook.title,
            description: playbook.description ?? null,
            category: playbook.category ?? null,
            tags: (playbook.tags ?? []).map((t) => t.name),
            node_count: playbook.node_count ?? 0,
            versions_count: playbook.versions_count ?? 0,
            graph: playbook.graph_json ?? null,
          },
          ["title", "description", "category", "tags", "graph"],
        );
      } catch (error) {
        return fail(error);
      }
    },
  );
}

// Authoring is confined to tagged playbooks and the fixed REST payload below.
const MAX_TAGS = 18;
const singleLine = (max: number, min = 0) => z.string().min(min).max(max)
  .refine(value => !/[\x00-\x1f\x7f-\x9f]/.test(value), "control characters are not allowed");
const freeText = (max: number, min = 0) => z.string().min(min).max(max)
  .refine(value => !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(value), "control characters are not allowed");
const writeFields = {
  title: singleLine(200, 1).refine(value => value.trim().length > 0, "title must not be blank"),
  description: freeText(8000).optional(),
  category: singleLine(100).optional(),
  tags: z.array(singleLine(100, 1).refine(value => value.trim().length > 0, "tag must not be blank")).max(MAX_TAGS).optional(),
  content_markdown: freeText(100000, 1).refine(value => value.trim().length > 0, "content must not be blank"),
};
const confirmed = z.literal(true).describe("Must be true to acknowledge the playbook write.");
const createInput = z.object({ ...writeFields, confirm: confirmed }).strict();
const updateInput = z.object({
  title: writeFields.title.optional(), description: writeFields.description,
  category: writeFields.category, tags: writeFields.tags,
  content_markdown: writeFields.content_markdown.optional(),
  playbook_id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), confirm: confirmed,
}).strict().refine(value => [value.title, value.description, value.category, value.tags, value.content_markdown]
  .some(field => field !== undefined), "at least one update field is required");
const resultId = z.object({ id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER) });

export function registerPlaybookWriteTools(server: McpServer, client: HotwashClient, policy: ToolPolicy): void {
  // Read-only servers must not list a state-changing tool at all.
  if (!policy.allowMutations) return;
  server.registerTool("hotwash_create_playbook", {
    description: "Create a draft playbook from Markdown. Requires HOTWASH_MCP_ALLOW_MUTATIONS=true and confirm: true. Always adds soc-bot and draft tags. Unknown fields are refused. Check existing playbooks before creating; do not retry an unconfirmed write blindly.",
    inputSchema: createInput, annotations: mutatingTool({ destructive: false, idempotent: false }),
  }, async args => {
    const blocked = guardMutation(policy, "create this playbook");
    if (blocked) return blocked;
    try {
      const { confirm: _, ...fields } = args;
      const tags = [...new Set([...(fields.tags ?? []).map(tag => tag.trim().toLowerCase().replace(/\s+/g, "-")), "soc-bot", "draft"])];
      // The mandatory tags are part of the request, so a full 18-tag list would
      // otherwise reach the API and come back as a 422.
      if (tags.length > MAX_TAGS) {
        throw new Error(`Refusing create: ${tags.length} tags exceed the ${MAX_TAGS}-tag limit; remove a tag from the request and retry`);
      }
      const result = resultId.safeParse(await client.createPlaybook({ ...fields, tags }));
      if (!result.success) throw new Error("Playbook write outcome not confirmed; check playbooks before retrying");
      return ok({ playbook_id: result.data.id, tags });
    } catch (error) { return fail(error); }
  });
  server.registerTool("hotwash_update_playbook", {
    description: "Update supplied fields of a playbook already tagged soc-bot. Fetches ownership first and refuses human-authored playbooks, then sends the updated_at it read as a precondition: if the playbook changed in between the write is refused and must be re-read. Tags are merged into the existing set: an update can add tags but never removes any (soc-bot and draft stay). Requires HOTWASH_MCP_ALLOW_MUTATIONS=true and confirm: true. Unknown fields and empty patches are refused. Check the playbook before retrying an unconfirmed write.",
    inputSchema: updateInput, annotations: mutatingTool({ destructive: true, idempotent: true }),
  }, async args => {
    const blocked = guardMutation(policy, "update this playbook");
    if (blocked) return blocked;
    try {
      const { playbook_id, confirm: _, ...fields } = args;
      let target;
      try { target = await client.getPlaybook(playbook_id); }
      catch { throw new Error("Refusing update: playbook ownership could not be verified"); }
      if (target?.id !== playbook_id || !Array.isArray(target.tags) || !target.tags.some(tag => tag?.name === "soc-bot")) {
        throw new Error("Refusing update: target playbook must already carry the soc-bot tag");
      }
      // Precondition from the ownership read above: the API rejects the write with
      // 409 if anything (a retag, another edit) landed in between.
      const readAt = target.updated_at;
      if (typeof readAt !== "string" || readAt.length === 0) {
        throw new Error("Refusing update: playbook version could not be verified");
      }
      // The API replaces the tag list, so merge: an update can add tags but never drop
      // existing ones (draft, human review markers) and always keeps soc-bot.
      const existing = target.tags.map(tag => tag?.name).filter((name): name is string => typeof name === "string");
      const merged = fields.tags === undefined ? undefined
        : [...new Set([...existing, ...fields.tags.map(tag => tag.trim().toLowerCase().replace(/\s+/g, "-")), "soc-bot"])];
      // Refuse here: the API would answer 422 and this tool would report the
      // misleading "outcome not confirmed" error for a request it never sent.
      if (merged !== undefined && merged.length > MAX_TAGS) {
        throw new Error(`Refusing update: ${merged.length} tags exceed the ${MAX_TAGS}-tag limit; remove a tag from the request and retry`);
      }
      const payload = { ...fields, ...(merged === undefined ? {} : { tags: merged }) };
      const result = resultId.safeParse(await client.updatePlaybook(playbook_id, payload, readAt));
      if (!result.success || result.data.id !== playbook_id) throw new Error("Playbook write outcome not confirmed; inspect the playbook before retrying");
      return ok({ playbook_id });
    } catch (error) { return fail(error); }
  });
}
