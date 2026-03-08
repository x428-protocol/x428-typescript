#!/usr/bin/env node
/**
 * x428 Demo MCP Server
 *
 * A minimal MCP server demonstrating x428 precondition guards
 * with different precondition requirements per tool.
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
import { x428Guard } from "../src/mcp/guard.js";

const server = new McpServer({
  name: "x428-demo",
  version: "0.1.0",
});

// Search: requires TOS acceptance only
server.tool(
  "search",
  "Search for information (requires TOS acceptance)",
  { query: z.string().describe("Search query") },
  x428Guard(
    {
      server: server.server,
      preconditions: [
        {
          type: "tos",
          documentUrl: "https://x428.org/demo-tos",
          tosVersion: "1.0",
          documentHash: "sha256-deadbeef",
        },
      ],
      resourceUri: "x428://mcp/tool/search",
    },
    async ({ query }: { query: string }) => {
      return {
        content: [
          {
            type: "text",
            text: `Search results for "${query}":\n\n1. Example result about ${query}\n2. Another result about ${query}\n3. More information on ${query}`,
          },
        ],
      };
    },
  ),
);

// Lookup: requires age verification only
server.tool(
  "lookup",
  "Look up a record by ID (requires age verification)",
  { id: z.string().describe("Record ID to look up") },
  x428Guard(
    {
      server: server.server,
      preconditions: [
        {
          type: "age",
          minimumAge: 18,
        },
      ],
      resourceUri: "x428://mcp/tool/lookup",
    },
    async ({ id }: { id: string }) => {
      return {
        content: [
          {
            type: "text",
            text: `Record ${id}:\n  Name: Example Record\n  Status: Active\n  Created: 2026-01-15`,
          },
        ],
      };
    },
  ),
);

// Info: requires both TOS + age
server.tool(
  "info",
  "Get detailed info (requires TOS acceptance and age verification)",
  { topic: z.string().describe("Topic to get info about") },
  x428Guard(
    {
      server: server.server,
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
      resourceUri: "x428://mcp/tool/info",
    },
    async ({ topic }: { topic: string }) => {
      return {
        content: [
          {
            type: "text",
            text: `Detailed info about "${topic}":\n\nThis is comprehensive information requiring both TOS acceptance and age verification.`,
          },
        ],
      };
    },
  ),
);

// Connect via stdio
const transport = new StdioServerTransport();
await server.connect(transport);
