#!/usr/bin/env node
/**
 * x428 Demo — MCP Apps Mode (HTTP)
 *
 * Uses MCP Apps for rich inline precondition acceptance UI.
 * Works with Claude Desktop and MCP Inspector's Apps tab.
 *
 * HTTP transport is used so stderr logging is visible and Claude Desktop
 * can connect via a tunnel.
 *
 * Usage:
 *   npx tsx examples/demo-server-apps.ts
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
import { x428Guard } from "@x428/mcp";
import { DEMO_TOOLS } from "./demo-tools.js";

const log = (...args: unknown[]) => process.stderr.write(`[x428-demo] ${args.map(String).join(" ")}\n`);

/** Create a fresh McpServer with x428-guarded tools. One per session. */
function createMcpServer() {
  const server = new McpServer({
    name: "x428-demo-apps",
    version: "0.1.0",
  });

  for (const tool of DEMO_TOOLS) {
    x428Guard(
      server,
      {
        preconditions: tool.preconditions,
        resourceUri: tool.resourceUri,
      },
      tool.name,
      {
        description: tool.description,
        inputSchema: tool.inputSchema,
      },
      tool.handler,
    );
  }

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

    const server = createMcpServer();
    await server.connect(transport);
    await transport.handleRequest(req, res);
    return;
  }

  if (req.method === "GET" && !sessionId) {
    res.writeHead(400);
    res.end("Missing session ID");
    return;
  }

  if (sessionId && !transports.has(sessionId)) {
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
