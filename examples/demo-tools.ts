/**
 * Shared tool definitions for x428 demo servers.
 *
 * Both the elicitation demo (stdio) and the MCP Apps demo (HTTP) use
 * the same set of tools with the same precondition configurations.
 */
import { z } from "zod";
import type { PreconditionConfig } from "@x428/core";

export interface DemoTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  preconditions: PreconditionConfig[];
  resourceUri: string;
  handler: (args: any) => Promise<{ content: Array<{ type: string; text: string }> }>;
}

export const DEMO_TOOLS: DemoTool[] = [
  {
    name: "search",
    description: "Search for information (requires TOS acceptance)",
    inputSchema: { query: z.string().describe("Search query") },
    preconditions: [
      {
        type: "tos",
        documentUrl: "https://x428.org/demo-tos",
        tosVersion: "1.0",
        documentHash: "sha256-deadbeef",
      },
    ],
    resourceUri: "x428://mcp/tool/search",
    handler: async ({ query }: { query: string }) => ({
      content: [{
        type: "text",
        text: `Search results for "${query}":\n\n1. Example result about ${query}\n2. Another result about ${query}\n3. More information on ${query}`,
      }],
    }),
  },
  {
    name: "lookup",
    description: "Look up a record by ID (requires age verification)",
    inputSchema: { id: z.string().describe("Record ID to look up") },
    preconditions: [
      {
        type: "age",
        minimumAge: 18,
      },
    ],
    resourceUri: "x428://mcp/tool/lookup",
    handler: async ({ id }: { id: string }) => ({
      content: [{
        type: "text",
        text: `Record ${id}:\n  Name: Example Record\n  Status: Active\n  Created: 2026-01-15`,
      }],
    }),
  },
  {
    name: "info",
    description: "Get detailed info (requires TOS acceptance and age verification)",
    inputSchema: { topic: z.string().describe("Topic to get info about") },
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
    handler: async ({ topic }: { topic: string }) => ({
      content: [{
        type: "text",
        text: `Detailed info about "${topic}":\n\nThis is comprehensive information requiring both TOS acceptance and age verification.`,
      }],
    }),
  },
];
