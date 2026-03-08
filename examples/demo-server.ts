#!/usr/bin/env node
/**
 * x428 Demo MCP Server
 *
 * A minimal MCP server demonstrating x428 precondition guards.
 * All tools require TOS acceptance and age verification before use.
 *
 * Usage:
 *   npx tsx examples/demo-server.ts
 *
 * Claude Desktop config (claude_desktop_config.json):
 *   {
 *     "mcpServers": {
 *       "x428-demo": {
 *         "command": "npx",
 *         "args": ["tsx", "<absolute-path>/x428-typescript/examples/demo-server.ts"]
 *       }
 *     }
 *   }
 *
 * MCP Inspector:
 *   npx @modelcontextprotocol/inspector npx tsx examples/demo-server.ts
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { x428Protect } from "../src/index.js";

const server = new McpServer({
  name: "x428-demo",
  version: "0.1.0",
});

// Gate all tools behind TOS + age verification
x428Protect(server, {
  preconditions: [
    {
      type: "tos",
      documentUrl: "https://x428.org/demo-tos",
      tosVersion: "1.0",
      documentHash: "sha256-deadbeef",
    },
    {
      type: "age",
      minimumAge: 18,
    },
  ],
});

// A simple search tool
server.tool(
  "search",
  "Search for information (requires TOS acceptance)",
  { query: z.string().describe("Search query") },
  async ({ query }) => {
    return {
      content: [
        {
          type: "text",
          text: `Search results for "${query}":\n\n1. Example result about ${query}\n2. Another result about ${query}\n3. More information on ${query}`,
        },
      ],
    };
  },
);

// A lookup tool
server.tool(
  "lookup",
  "Look up a record by ID (requires TOS acceptance)",
  { id: z.string().describe("Record ID to look up") },
  async ({ id }) => {
    return {
      content: [
        {
          type: "text",
          text: `Record ${id}:\n  Name: Example Record\n  Status: Active\n  Created: 2026-01-15`,
        },
      ],
    };
  },
);

// Connect via stdio
const transport = new StdioServerTransport();
await server.connect(transport);
