import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { HotwashClient } from "./client.js";
import { getConfig } from "./config.js";
import { registerArtifactTools } from "./tools/artifacts.js";
import { registerPlaybookTools } from "./tools/playbooks.js";
import { registerRunTools } from "./tools/runs.js";

async function main(): Promise<void> {
  const config = getConfig();

  const server = new McpServer({
    name: "hotwash-mcp",
    version: "0.1.0",
    description:
      "Drive Hotwash incident response playbooks: list playbooks, start runs against incidents, advance steps, attach evidence, and query timelines. Wraps the Hotwash REST API.",
  });

  const client = new HotwashClient(config);

  registerPlaybookTools(server, client);
  registerRunTools(server, client);
  registerArtifactTools(server, client);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("hotwash-mcp failed to start:", error);
  process.exit(1);
});
