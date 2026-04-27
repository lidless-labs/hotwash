import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, ok } from "./_util.js";

export function registerPlaybookTools(server: McpServer, client: HotwashClient): void {
  server.tool(
    "hotwash_list_playbooks",
    "List playbooks in the Hotwash library. Optional filters by category, tag, or search string. Returns id, title, category, tag list, and node count for each match.",
    {
      category: z.string().optional().describe("Filter by category, e.g. 'Incident Response', 'Vulnerability', 'Threat Hunting'."),
      tag: z.string().optional().describe("Filter by tag name."),
      search: z.string().optional().describe("Free-text search across title and description."),
    },
    async ({ category, tag, search }) => {
      try {
        const playbooks = await client.listPlaybooks({ category, tag, search });
        return ok(
          playbooks.map((p) => ({
            id: p.id,
            title: p.title,
            category: p.category ?? null,
            tags: (p.tags ?? []).map((t) => t.name),
            node_count: p.node_count ?? 0,
            description: p.description ?? null,
          })),
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
    async ({ playbook_id }) => {
      try {
        const playbook = await client.getPlaybook(playbook_id);
        return ok({
          id: playbook.id,
          title: playbook.title,
          description: playbook.description ?? null,
          category: playbook.category ?? null,
          tags: (playbook.tags ?? []).map((t) => t.name),
          node_count: playbook.node_count ?? 0,
          versions_count: playbook.versions_count ?? 0,
          graph: playbook.graph_json ?? null,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );
}
