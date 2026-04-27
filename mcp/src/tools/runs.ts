import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, ok, refuseUnconfirmed } from "./_util.js";

const STEP_STATUSES = ["not_started", "in_progress", "completed", "skipped", "blocked"] as const;

export function registerRunTools(server: McpServer, client: HotwashClient): void {
  server.tool(
    "hotwash_start_run",
    "Start a new playbook execution for an incident. The playbook's nodes are cloned into per-step state (not_started). Returns the new execution id and step counters; pair with query_run to inspect the steps.",
    {
      playbook_id: z.number().int().positive().describe("Playbook id from list_playbooks."),
      incident_title: z.string().min(1).describe("Short human-readable title, e.g. 'Ransomware on PROD-DB-01'."),
      incident_id: z.string().optional().describe("External incident reference (ticket id, alert id, etc.)."),
      started_by: z.string().optional().describe("Analyst or system identifier kicking off the run."),
      context: z.record(z.string(), z.any()).optional().describe("Free-form context attached to the run, e.g. a Wazuh alert payload, IOC list, or hostname."),
    },
    async (args) => {
      try {
        const summary = await client.startRun(args);
        return ok({
          execution_id: summary.id,
          status: summary.status,
          incident_title: summary.incident_title,
          playbook_id: summary.playbook_id,
          playbook_title: summary.playbook_title ?? null,
          steps_total: summary.steps_total,
          steps_completed: summary.steps_completed,
          started_at: summary.started_at,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "hotwash_query_run",
    "Get current state of an execution: status, the full step list with statuses/evidence/notes, and optionally the timeline. Note that the steps array includes phase-marker nodes (node_type='phase'), but execution.steps_total and steps_completed exclude them, so steps.length will usually be larger than steps_total. Iterate over steps where node_type !== 'phase' for actionable items.",
    {
      execution_id: z.number().int().positive(),
      include_timeline: z.boolean().optional().describe("Also return the chronological event log (returned in reverse-chronological order, newest first)."),
    },
    async ({ execution_id, include_timeline }) => {
      try {
        const detail = await client.getRun(execution_id);
        const payload: Record<string, unknown> = {
          execution: detail.execution,
          steps: detail.steps,
          playbook_title: detail.playbook_title ?? null,
        };
        if (include_timeline) {
          payload.timeline = await client.getTimeline(execution_id);
        }
        return ok(payload);
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "hotwash_advance_step",
    "Update a single step in an execution: change status, assign an analyst, append a note, or record a decision. Returns the refreshed execution detail.",
    {
      execution_id: z.number().int().positive(),
      node_id: z.string().min(1).describe("The step's node_id from query_run."),
      status: z.enum(STEP_STATUSES).optional().describe("New step status. 'completed' and 'skipped' set completed_at; 'in_progress' sets started_at on first transition."),
      assignee: z.string().optional().describe("Analyst handling this step. Empty string clears."),
      note: z.string().optional().describe("Append a free-form note to the step's note list."),
      decision_taken: z.string().optional().describe("For decision nodes, which option was chosen (must be one of decision_options)."),
    },
    async ({ execution_id, node_id, status, assignee, note, decision_taken }) => {
      try {
        const detail = await client.advanceStep(execution_id, node_id, {
          status,
          assignee,
          notes: note,
          decision_taken,
        });
        const updated = detail.steps.find((s) => s.node_id === node_id);
        return ok({
          execution: detail.execution,
          step: updated ?? null,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.tool(
    "hotwash_cancel_run",
    "Abandon an in-progress execution. Sets status=abandoned and stamps completed_at; the run remains queryable for the audit log. Destructive: requires confirm: true.",
    {
      execution_id: z.number().int().positive(),
      reason: z.string().optional().describe("Free-form reason recorded as an execution note."),
      confirm: z.literal(true).describe("Must be true. Acknowledges the run will be marked abandoned."),
    },
    async ({ execution_id, reason, confirm }) => {
      if (!confirm) return refuseUnconfirmed("abandon this execution");
      try {
        if (reason) {
          await client.patchExecution(execution_id, { notes: reason });
        }
        const summary = await client.patchExecution(execution_id, { status: "abandoned" });
        return ok({
          execution_id: summary.id,
          status: summary.status,
          completed_at: summary.completed_at,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );
}
