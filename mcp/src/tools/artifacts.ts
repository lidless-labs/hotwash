import { Buffer } from "node:buffer";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { HotwashClient } from "../client.js";
import { fail, ok } from "./_util.js";

export function registerArtifactTools(server: McpServer, client: HotwashClient): void {
  server.tool(
    "hotwash_attach_artifact",
    "Attach a text or base64-encoded binary artifact (e.g. a log snippet, screenshot, hash list) to a step in a running execution. Either text or base64 must be provided.",
    {
      execution_id: z.number().int().positive(),
      node_id: z.string().min(1).describe("Step node_id from query_run."),
      filename: z.string().min(1).describe("Filename to save under, e.g. 'ioc-list.txt'."),
      text: z.string().optional().describe("UTF-8 text content. Use for log snippets, JSON dumps, etc."),
      base64: z.string().optional().describe("Base64-encoded binary content. Use for images or non-text artifacts."),
    },
    async ({ execution_id, node_id, filename, text, base64 }) => {
      if (!text && !base64) {
        return fail(new Error("Provide either 'text' or 'base64' content for the artifact."));
      }
      if (text && base64) {
        return fail(new Error("Provide either 'text' or 'base64', not both."));
      }
      try {
        const bytes = text !== undefined ? Buffer.from(text, "utf8") : Buffer.from(base64!, "base64");
        const step = await client.attachArtifact(
          execution_id,
          node_id,
          filename,
          new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
        );
        return ok({
          node_id: step.node_id,
          evidence: step.evidence,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );
}
