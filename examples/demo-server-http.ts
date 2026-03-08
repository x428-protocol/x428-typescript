#!/usr/bin/env node
/**
 * x428 Demo MCP Server — HTTP transport for debugging.
 *
 * Run standalone so stderr is visible, then connect Inspector or Claude Desktop.
 *
 * Usage:
 *   npx tsx examples/demo-server-http.ts
 *   npx @modelcontextprotocol/inspector --transport http --server-url http://localhost:3428/mcp
 *
 * For Claude Desktop (via tunnel):
 *   cloudflared tunnel --url http://localhost:3428
 *   # Add https://<tunnel>/mcp as streamable HTTP server in Claude Desktop
 */
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { x428Guard } from "../src/mcp/guard.js";

const log = (...args: unknown[]) => process.stderr.write(`[x428-demo] ${args.map(String).join(" ")}\n`);

/** Create a fresh McpServer with x428-guarded tools. One per session. */
function createServer_() {
  const server = new McpServer({
    name: "x428-demo",
    version: "0.1.0",
  });

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

  return server;
}

// Session tracking
const transports = new Map<string, StreamableHTTPServerTransport>();

const httpServer = createServer(async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  log(`${req.method} ${req.url} session=${sessionId ?? "(none)"}`);

  // CORS
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

  // New session (POST without session ID = initialization)
  if (req.method === "POST" && !sessionId) {
    log("  -> creating new session");

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sid) => {
        transports.set(sid, transport);
        log(`  -> session initialized: ${sid}`);
      },
    });

    transport.onclose = () => {
      for (const [sid, t] of transports) {
        if (t === transport) {
          transports.delete(sid);
          log(`Session closed: ${sid}`);
          break;
        }
      }
    };

    // New McpServer per session (SDK pattern)
    const server = createServer_();

    // Log initialize request
    const rawServer = (server as any).server;
    if (rawServer._requestHandlers) {
      const origInit = rawServer._requestHandlers.get("initialize");
      if (origInit) {
        rawServer._requestHandlers.set("initialize", async (req: any, extra: any) => {
          log(`>> initialize request: ${JSON.stringify(req.params)}`);
          const result = await origInit(req, extra);
          log(`<< initialize response: ${JSON.stringify(result, null, 2)}`);
          // Log capabilities after init
          const caps = rawServer.getClientCapabilities?.();
          log(`Client capabilities (post-Zod): ${JSON.stringify(caps)}`);
          return result;
        });
      }

      // Log tools/call requests
      const origToolsCall = rawServer._requestHandlers.get("tools/call");
      if (origToolsCall) {
        rawServer._requestHandlers.set("tools/call", async (req: any, extra: any) => {
          log(`>> tools/call: ${JSON.stringify(req.params)}`);
          const result = await origToolsCall(req, extra);
          log(`<< tools/call result: ${JSON.stringify(result, null, 2)}`);
          return result;
        });
      }

      // Log tools/list requests
      const origToolsList = rawServer._requestHandlers.get("tools/list");
      if (origToolsList) {
        rawServer._requestHandlers.set("tools/list", async (req: any, extra: any) => {
          log(`>> tools/list`);
          const result = await origToolsList(req, extra);
          const names = result.tools?.map((t: any) => t.name) ?? [];
          log(`<< tools/list: [${names.join(", ")}]`);
          return result;
        });
      }
    }

    await server.connect(transport);
    await transport.handleRequest(req, res);
    return;
  }

  // GET without session = SSE stream request without valid session
  if (req.method === "GET" && !sessionId) {
    res.writeHead(400);
    res.end("Missing session ID");
    return;
  }

  // Unknown session
  if (sessionId && !transports.has(sessionId)) {
    log(`  -> 404: unknown session ${sessionId}`);
    res.writeHead(404);
    res.end("Session not found");
    return;
  }

  res.writeHead(400);
  res.end("Bad request");
});

const PORT = 3428;
httpServer.listen(PORT, () => {
  log(`Listening on http://localhost:${PORT}/mcp`);
});
