import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpServer, stripToolSchemaDialect } from "./server.js";
import { startHttpServer } from "./http.js";

async function main(): Promise<void> {
  if (process.argv.includes("--http")) {
    await startHttpServer();
    return;
  }
  const server = createMcpServer();

  const transport = new StdioServerTransport();
  stripToolSchemaDialect(transport);
  await server.connect(transport);
}

main().catch((error) => {
  console.error("hotwash-mcp failed to start:", error);
  process.exit(1);
});
