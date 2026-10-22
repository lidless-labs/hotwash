import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { HotwashClient } from "./client.js";
import { getConfig, type HotwashConfig } from "./config.js";
import { registerArtifactTools } from "./tools/artifacts.js";
import { registerPlaybookTools } from "./tools/playbooks.js";
import { registerRunTools } from "./tools/runs.js";
import { registerSuggestionTools } from "./tools/suggestions.js";

// Protocol registrations and client configuration belong to one MCP session.
export function createMcpServer(config: HotwashConfig = getConfig()): McpServer {
  const server = new McpServer({
    name: "hotwash-mcp",
    version: "0.3.0",
    description:
      "Drive Hotwash incident response playbooks: list playbooks, start runs against incidents, advance steps, attach evidence, query timelines, and review the Wazuh ingest suggestion queue. Wraps the Hotwash REST API.",
  });

  const client = new HotwashClient(config);
  const policy = { allowMutations: config.allowMutations === true };

  registerPlaybookTools(server, client);
  registerRunTools(server, client, policy);
  registerArtifactTools(server, client, policy);
  registerSuggestionTools(server, client, policy);

  return server;
}

// Anthropic rejects draft-07 schema markers when the full tool set is sent.
// Apply the existing stdio compatibility behavior to both transports.
export function stripToolSchemaDialect(transport: Transport): void {
  const send = transport.send.bind(transport);
  transport.send = (message, options) => {
    const tools = "result" in message ? message.result.tools : undefined;
    if (Array.isArray(tools)) {
      for (const tool of tools) {
        if (tool?.inputSchema) delete tool.inputSchema.$schema;
        if (tool?.outputSchema) delete tool.outputSchema.$schema;
      }
    }
    return send(message, options);
  };
}
