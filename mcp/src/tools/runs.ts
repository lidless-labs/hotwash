import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, guardMutation, mutatingTool, ok, READ_ONLY_TOOL, refuseUnconfirmed, type ToolPolicy } from "./_util.js";
import { readResult } from "./_read.js";
import type { ExecutionEvidence, ExecutionSummary } from "../types.js";

const STEP_STATUSES = ["not_started", "in_progress", "completed", "skipped", "blocked"] as const;

function runSummary(run: ExecutionSummary) {
  if (!Number.isSafeInteger(run.id) || run.id <= 0 || typeof run.status !== "string") {
    throw new Error("Invalid run response");
  }
  const { id, status, playbook_id, playbook_title, incident_title, incident_id,
    started_at, completed_at, steps_total, steps_completed } = run;
  return { id, status, playbook_id, playbook_title, incident_title, incident_id,
    started_at, completed_at, steps_total, steps_completed };
}

function recordedEvidence(evidence: ExecutionEvidence & { connector?: unknown; action?: unknown; result?: unknown }, gaps: string[]) {
  const { filename, size, uploaded_at, sha256, source_tool, source_ref, observed_at } = evidence;
  const attachment = { filename, size, uploaded_at, sha256, source_tool, source_ref, observed_at };
  if (evidence.connector === undefined && evidence.action === undefined && evidence.result === undefined) return attachment;
  const { connector, action, result } = evidence;
  if (connector !== "thehive" || !["create_case", "add_observable", "run_analyzer"].includes(String(action))) {
    gaps.push("unsupported_connector_evidence");
    return attachment;
  }
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    gaps.push("malformed_connector_evidence");
    return attachment;
  }
  const raw = result as Record<string, unknown>;
  if (raw.truncated === true) {
    gaps.push("connector_evidence_truncated");
    return attachment;
  }
  const key = action === "create_case" ? "case_id" : action === "add_observable" ? "observable_id" : "job_id";
  const parsed = z.object({
    [key]: z.string().max(128).regex(/^~[A-Za-z0-9]+(?![\s\S])/),
    ...(action === "run_analyzer" ? { status: z.string().min(1).max(128).nullable() } : {}),
  }).safeParse(raw);
  if (!parsed.success) {
    gaps.push("malformed_connector_evidence");
    return attachment;
  }
  gaps.push("connector_association_unverified");
  return { ...attachment, recorded_connector_evidence: {
    connector, action, ...parsed.data, association: "unverified",
  } };
}

export function registerRunTools(server: McpServer, client: HotwashClient, policy?: ToolPolicy): void {
  server.registerTool("hotwash_list_runs", {
    description: "Read a bounded inventory of existing runs. This is not authoritative finding dedup. Fetches one extra row to report overflow; never starts or advances a run.",
    inputSchema: z.object({
      status: z.enum(["active", "paused", "completed", "abandoned"]).optional(),
      playbook_id: z.number().int().positive().optional(),
      limit: z.number().int().min(1).max(100).default(50),
    }).strict(), annotations: READ_ONLY_TOOL,
  }, async ({ limit, ...filters }) => {
    try {
      const rows = await client.listRuns({ ...filters, limit: limit + 1 });
      if (!Array.isArray(rows) || rows.length > limit + 1) throw new Error("Invalid run inventory");
      const runs = rows.slice(0, limit).map(runSummary);
      return readResult({ runs, returned: runs.length, limit, has_more: rows.length > limit,
        overflow: rows.length > limit, observed_at: new Date().toISOString(), coverage: "unverified",
        gaps: ["inventory_only", "identity_unbound", ...(rows.length > limit ? ["overflow"] : [])] });
    } catch { return fail(new Error("Hotwash read failed; run inventory unavailable")); }
  });

  server.registerTool("hotwash_get_run_report", {
    description: "Read the existing JSON report of a known run, with selected steps, timeline and metrics. No state changes or evidence attachments. Truncation and identity gaps remain explicit.",
    inputSchema: z.object({ execution_id: z.number().int().positive() }).strict(), annotations: READ_ONLY_TOOL,
  }, async ({ execution_id }) => {
    try {
      const source = await client.getRunReport(execution_id);
      const execution = runSummary(source.execution);
      if (execution.id !== execution_id) throw new Error("Invalid report identity");
      const { total_duration, steps_completed, steps_total, mean_step_time, bottleneck_step, bottleneck_time } = source.metrics;
      const gaps = ["report_snapshot", "identity_unbound"];
      const report = {
        execution, playbook_title: source.playbook_title,
        metrics: { total_duration, steps_completed, steps_total, mean_step_time, bottleneck_step, bottleneck_time },
        steps: source.steps.map(step => ({
          node_id: step.node_id, node_type: step.node_type, node_label: step.node_label, phase: step.phase,
          status: step.status, assignee: step.assignee, notes: step.notes,
          decision_taken: step.decision_taken, started_at: step.started_at, completed_at: step.completed_at, duration: step.duration,
          evidence: (step.evidence ?? []).map(evidence => recordedEvidence(evidence, gaps)),
        })),
        timeline: source.timeline.map(({ timestamp, event_type, actor, description }) => ({ timestamp, event_type, actor, description })),
      };
      return readResult({ report, observed_at: new Date().toISOString(), coverage: "unverified", gaps: [...new Set(gaps)] });
    } catch { return fail(new Error(`Hotwash read failed; run ${execution_id} report unavailable`)); }
  });

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
    mutatingTool({ destructive: false, idempotent: false }),
    async (args) => {
      const blocked = guardMutation(policy, "start a run");
      if (blocked) return blocked;
      try {
        const summary = await client.startRun(args);
        return ok(
          {
            execution_id: summary.id,
            status: summary.status,
            incident_title: summary.incident_title,
            playbook_id: summary.playbook_id,
            playbook_title: summary.playbook_title ?? null,
            steps_total: summary.steps_total,
            steps_completed: summary.steps_completed,
            started_at: summary.started_at,
          },
          ["playbook_title"],
        );
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
    READ_ONLY_TOOL,
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
        return ok(payload, [
          "execution.incident_title",
          "execution.incident_id",
          "execution.playbook_title",
          "steps[].node_label",
          "steps[].phase",
          "steps[].assignee",
          "steps[].notes",
          "steps[].decision_options",
          "steps[].evidence",
          "playbook_title",
          "timeline[].description",
          "timeline[].actor",
        ]);
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
    mutatingTool({ destructive: true, idempotent: false }),
    async ({ execution_id, node_id, status, assignee, note, decision_taken }) => {
      const blocked = guardMutation(policy, "update this step");
      if (blocked) return blocked;
      try {
        const detail = await client.advanceStep(execution_id, node_id, {
          status,
          assignee,
          notes: note,
          decision_taken,
        });
        const updated = detail.steps.find((s) => s.node_id === node_id);
        return ok(
          {
            execution: detail.execution,
            step: updated ?? null,
          },
          [
            "execution.incident_title",
            "execution.incident_id",
            "execution.playbook_title",
            "step.node_label",
            "step.assignee",
            "step.notes",
            "step.decision_options",
            "step.evidence",
          ],
        );
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
    mutatingTool({ destructive: true, idempotent: false }),
    async ({ execution_id, reason, confirm }) => {
      const blocked = guardMutation(policy, "abandon this execution");
      if (blocked) return blocked;
      if (!confirm) return refuseUnconfirmed("abandon this execution");
      try {
        if (reason) {
          await client.patchExecution(execution_id, { notes: reason });
        }
        const summary = await client.patchExecution(execution_id, { status: "abandoned", confirm: true });
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
