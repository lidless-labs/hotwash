import { Buffer } from "node:buffer";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, guardMutation, mutatingTool, ok, type ToolPolicy } from "./_util.js";

const MAX_EVIDENCE_BYTES = 25 * 1024 * 1024;
const MAX_BASE64_CHARS = 4 * Math.ceil(MAX_EVIDENCE_BYTES / 3);

function artifactBytes(text: string | undefined, base64: string | undefined): Buffer {
  if (text !== undefined) {
    if (text.length > MAX_EVIDENCE_BYTES || Buffer.byteLength(text, "utf8") > MAX_EVIDENCE_BYTES) {
      throw new Error("Artifact exceeds the 25 MiB evidence size limit.");
    }
    return Buffer.from(text, "utf8");
  }
  const encoded = base64!;
  if (encoded.length > MAX_BASE64_CHARS) {
    throw new Error("Artifact exceeds the 25 MiB evidence size limit.");
  }
  // Require canonical standard base64. Node's decoder silently ignores invalid
  // characters, incomplete quartets and nonzero padding bits.
  const padding = encoded.endsWith("==") ? 2 : encoded.endsWith("=") ? 1 : 0;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const last = alphabet.indexOf(encoded[encoded.length - padding - 1]);
  if (encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)
      || (padding === 2 && (last & 15) !== 0) || (padding === 1 && (last & 3) !== 0)) {
    throw new Error("Artifact must contain valid padded base64.");
  }
  const decodedSize = (encoded.length / 4) * 3 - padding;
  if (decodedSize > MAX_EVIDENCE_BYTES) {
    throw new Error("Artifact exceeds the 25 MiB evidence size limit.");
  }
  return Buffer.from(encoded, "base64");
}

export function registerArtifactTools(server: McpServer, client: HotwashClient, policy?: ToolPolicy): void {
  server.tool(
    "hotwash_attach_artifact",
    "Attach a text or base64-encoded binary artifact (e.g. a log snippet, screenshot, hash list) to a step in a running execution. Either text or base64 must be provided.",
    {
      execution_id: z.number().int().positive(),
      node_id: z.string().min(1).describe("Step node_id from query_run."),
      filename: z.string().min(1).describe("Filename to save under, e.g. 'ioc-list.txt'."),
      source_tool: z.string().min(1).max(1024).optional().describe("Originating tool name, retained as artifact provenance."),
      source_ref: z.string().min(1).max(1024).optional().describe("Opaque upstream reference. Never fetched by Hotwash."),
      observed_at: z.string().datetime({ offset: true }).max(64).regex(/(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$/).optional().describe("RFC3339 observation time with an explicit offset."),
      text: z.string().max(MAX_EVIDENCE_BYTES).optional().describe("UTF-8 text content. Use for log snippets, JSON dumps, etc."),
      base64: z.string().max(MAX_BASE64_CHARS).optional().describe("Base64-encoded binary content. Use for images or non-text artifacts."),
    },
    mutatingTool({ destructive: false, idempotent: false }),
    async ({ execution_id, node_id, filename, text, base64, source_tool, source_ref, observed_at }) => {
      const blocked = guardMutation(policy, "attach this artifact");
      if (blocked) return blocked;
      if (!text && !base64) {
        return fail(new Error("Provide either 'text' or 'base64' content for the artifact."));
      }
      if (text !== undefined && base64 !== undefined) {
        return fail(new Error("Provide either 'text' or 'base64', not both."));
      }
      try {
        const bytes = artifactBytes(text, base64);
        const step = await client.attachArtifact(
          execution_id,
          node_id,
          filename,
          new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
          { source_tool, source_ref, observed_at },
        );
        return ok(
          {
            node_id: step.node_id,
            evidence: step.evidence,
          },
          ["evidence"],
        );
      } catch (error) {
        return fail(error);
      }
    },
  );
}
