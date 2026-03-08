#!/usr/bin/env node
/**
 * x428 Demo — Elicitation Mode (stdio)
 *
 * Uses elicitation dialogs (checkboxes) for precondition acceptance.
 * Works with MCP Inspector's Tools tab and any client that supports
 * the elicitation capability.
 *
 * Usage:
 *   npx tsx examples/demo-server.ts
 *
 * MCP Inspector:
 *   npx @modelcontextprotocol/inspector npx tsx examples/demo-server.ts
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { x428GuardElicitation } from "../src/mcp/guard.js";
import { DEMO_TOOLS } from "./demo-tools.js";

const server = new McpServer({
  name: "x428-demo-elicitation",
  version: "0.1.0",
});

for (const tool of DEMO_TOOLS) {
  server.tool(
    tool.name,
    tool.description,
    tool.inputSchema,
    x428GuardElicitation(
      {
        server: server.server,
        preconditions: tool.preconditions,
        resourceUri: tool.resourceUri,
      },
      tool.handler,
    ),
  );
}

const transport = new StdioServerTransport();
await server.connect(transport);
