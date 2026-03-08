#!/usr/bin/env node
/**
 * x428 Demo MCP Server — HTTP transport for debugging.
 *
 * Run standalone so stderr is visible, then connect Inspector via --transport http.
 *
 * Usage:
 *   npx tsx examples/demo-server-http.ts
 *   # In another terminal:
 *   npx @modelcontextprotocol/inspector --transport http --server-url http://localhost:3428/mcp
 */
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { x428Guard } from "../src/mcp/guard.js";

const log = (...args: unknown[]) => process.stderr.write(`[x428-demo] ${args.map(String).join(" ")}\n`);

const server = new McpServer({
  name: "x428-demo",
  version: "0.1.0",
});

log("Registering tools...");

// Search: requires TOS acceptance only
x428Guard(
  server,
  {
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
  "search",
  {
    description: "Search for information (requires TOS acceptance)",
    inputSchema: { query: z.string().describe("Search query") },
  },
  async ({ query }: { query: string }) => {
    log(`search handler called with query="${query}"`);
    return {
      content: [{ type: "text", text: `Search results for "${query}":\n1. Example result\n2. Another result` }],
    };
  },
);

log("Tools registered: search, x428/attest");

// Log internal state
const rawServer = (server as any).server;
log(`McpServer internal keys: ${Object.keys(server).filter(k => k.startsWith("_")).join(", ")}`);

// Intercept the low-level server to log tools/list and tools/call responses
if (rawServer._requestHandlers) {
  for (const method of ["tools/list", "tools/call", "resources/list", "resources/read"]) {
    const orig = rawServer._requestHandlers.get(method);
    if (orig) {
      rawServer._requestHandlers.set(method, async (req: any, extra: any) => {
        log(`>> ${method} request: ${JSON.stringify(req.params ?? {})}`);
        const result = await orig(req, extra);
        log(`<< ${method} response: ${JSON.stringify(result, null, 2)}`);
        return result;
      });
    }
  }
  log("Intercepted request handlers for logging");
}

// Single transport per connection
const transports = new Map<string, StreamableHTTPServerTransport>();

const httpServer = createServer(async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  log(`${req.method} ${req.url} session=${sessionId ?? "(none)"}`);

  // CORS for Inspector
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Expose-Headers", "*");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url !== "/mcp") {
    res.writeHead(404);
    res.end("Not found");
    return;
  }

  // Existing session
  if (sessionId && transports.has(sessionId)) {
    log(`  -> existing session ${sessionId}`);
    await transports.get(sessionId)!.handleRequest(req, res);
    return;
  }

  // New session (initialization POST without session ID)
  if (req.method === "POST") {
    log("  -> creating new session");
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });

    transport.onclose = () => {
      // Find and remove this transport
      for (const [sid, t] of transports) {
        if (t === transport) {
          transports.delete(sid);
          log(`Session closed: ${sid}`);
          break;
        }
      }
    };

    await server.connect(transport);
    await transport.handleRequest(req, res);

    // The transport sets session ID internally — find it from the response header
    // StreamableHTTPServerTransport sets Mcp-Session-Id in the response
    const responseSid = res.getHeader("mcp-session-id") as string | undefined;
    if (responseSid) {
      transports.set(responseSid, transport);
      log(`  -> new session created: ${responseSid}`);
    } else {
      log("  -> WARNING: no session ID in response");
    }
    return;
  }

  log(`  -> 400: no session for ${req.method}`);
  res.writeHead(400);
  res.end("Bad request - no valid session");
});

const PORT = 3428;
httpServer.listen(PORT, () => {
  log(`Listening on http://localhost:${PORT}/mcp`);
  log("Connect Inspector: npx @modelcontextprotocol/inspector --transport http --server-url http://localhost:3428/mcp");
});
