import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { x428Guard } from "@x428/mcp";
import {
  initTables,
  SqliteNonceStore,
  SqliteChallengeStore,
  SqliteTokenStore,
  SqliteAuditLog,
} from "./storage.js";
import { DEMO_TOOLS } from "./demo-tools.js";

interface Env {
  X428_MCP: DurableObjectNamespace;
}

export class X428McpAgent extends McpAgent<Env, {}, {}> {
  server = new McpServer({
    name: "x428-demo-workers",
    version: "0.1.0",
  });

  async init() {
    const sql = this.ctx.storage.sql;
    initTables(sql as any);

    const nonceStore = new SqliteNonceStore(sql as any);

    for (const tool of DEMO_TOOLS) {
      x428Guard(
        this.server as any,
        {
          preconditions: tool.preconditions,
          resourceUri: tool.resourceUri,
          nonceStore,
        },
        tool.name,
        {
          description: tool.description,
          inputSchema: tool.inputSchema,
        },
        tool.handler,
      );
    }
  }
}
