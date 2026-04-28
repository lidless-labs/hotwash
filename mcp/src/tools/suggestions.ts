import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, ok, refuseUnconfirmed } from "./_util.js";

const SUGGESTION_STATES = ["pending", "accepted", "dismissed"] as const;

export function registerSuggestionTools(server: McpServer, client: HotwashClient): void {
  server.tool(
    "hotwash_list_suggestions",
    "List ingest suggestions queued from `mode=suggest` Wazuh mappings. Returns the queue an analyst can review and act on. Defaults to state='pending' (the actionable queue). Filter by mapping_id to inspect a specific integration. Pair with hotwash_accept_suggestion to promote a row into a real execution.",
    {
      state: z.enum(SUGGESTION_STATES).optional().describe("Filter by lifecycle state. Defaults to 'pending' on the server."),
      mapping_id: z.number().int().positive().optional().describe("Filter to a single mapping (e.g. one Wazuh integration)."),
      limit: z.number().int().positive().max(500).optional().describe("Max rows to return. Server caps at 500; default is 100."),
    },
    async ({ state, mapping_id, limit }) => {
      try {
        const rows = await client.listSuggestions({ state, mapping_id, limit });
        return ok({
          count: rows.length,
          suggestions: rows.map((row) => ({
            id: row.id,
            state: row.state,
            mapping_id: row.mapping_id,
            playbook_id: row.playbook_id,
            rule_id: row.rule_id ?? null,
            agent_name: row.agent_name ?? null,
            description: row.description ?? null,
            accepted_execution_id: row.accepted_execution_id ?? null,
            created_at: row.created_at,
            resolved_at: row.resolved_at ?? null,
          })),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "hotwash_accept_suggestion",
    "Promote a pending ingest suggestion into a real Execution. The suggestion's stored Wazuh alert is attached as context.wazuh_alert on the new execution, identical to a `mode=auto` dispatch. Idempotent: re-accepting an already-accepted suggestion returns the existing execution rather than creating a duplicate. Pair with hotwash_query_run to inspect the resulting execution. Destructive (creates an execution and transitions the suggestion's state): requires confirm: true.",
    {
      suggestion_id: z.number().int().positive(),
      confirm: z.literal(true).describe("Must be true. Acknowledges a new execution will be created from this suggestion."),
    },
    async ({ suggestion_id, confirm }) => {
      if (!confirm) return refuseUnconfirmed("accept this suggestion");
      try {
        const response = await client.acceptSuggestion(suggestion_id);
        return ok({
          execution_id: response.execution.id,
          status: response.execution.status,
          incident_title: response.execution.incident_title,
          playbook_id: response.execution.playbook_id,
          playbook_title: response.execution.playbook_title ?? null,
          steps_total: response.execution.steps_total,
          steps_completed: response.execution.steps_completed,
          started_at: response.execution.started_at,
          already_accepted: response.already_accepted,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "hotwash_dismiss_suggestion",
    "Dismiss a pending ingest suggestion. Records the decision and anchors the cooldown window for that fingerprint, suppressing immediate re-fires of the same alert. Use when the suggestion is confirmed noise or otherwise should not become an execution. Reason is optional, max 500 chars, intentionally not persisted (only its presence and length are logged). Not reversible. Returns 409 if the suggestion is not pending. Destructive (transitions suggestion state and anchors cooldown): requires confirm: true.",
    {
      suggestion_id: z.number().int().positive(),
      reason: z
        .string()
        .max(500)
        .optional()
        .describe("Optional human-readable reason. Not persisted; only whether a reason was provided and its length are logged."),
      confirm: z
        .literal(true)
        .describe("Must be true. Acknowledges the suggestion will be dismissed and a cooldown anchor written for its fingerprint."),
    },
    async ({ suggestion_id, reason, confirm }) => {
      if (!confirm) return refuseUnconfirmed("dismiss this suggestion");
      try {
        const row = await client.dismissSuggestion(suggestion_id, reason);
        return ok({
          id: row.id,
          state: row.state,
          mapping_id: row.mapping_id,
          playbook_id: row.playbook_id,
          rule_id: row.rule_id ?? null,
          agent_name: row.agent_name ?? null,
          description: row.description ?? null,
          accepted_execution_id: row.accepted_execution_id ?? null,
          created_at: row.created_at,
          resolved_at: row.resolved_at ?? null,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );
}
