import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { x428Guard } from "@x428/mcp";
import {
  KvChallengeStore,
  KvTokenStore,
  KvAcceptedPreconditionStore,
  initAuditTable,
  SqliteAuditLog,
} from "./storage.js";
import { DEMO_TOOLS } from "./demo-tools.js";

interface Env {
  MCP_OBJECT: DurableObjectNamespace;
  X428_KV: KVNamespace;
}

export class X428McpAgent extends McpAgent<Env, {}, {}> {
  server = new McpServer({
    name: "x428-demo-workers",
    version: "0.1.0",
  });

  async init() {
    // KV-backed stores — shared across all DOs (cross-session)
    const challengeStore = new KvChallengeStore(this.env.X428_KV);
    const tokenStore = new KvTokenStore(this.env.X428_KV);
    const acceptedPreconditionStore = new KvAcceptedPreconditionStore(this.env.X428_KV);

    // SQLite audit log — per-DO, append-only
    const sql = this.ctx.storage.sql;
    initAuditTable(sql as any);
    const auditLog = new SqliteAuditLog(sql as any);

    for (const tool of DEMO_TOOLS) {
      x428Guard(
        this.server as any,
        {
          preconditions: tool.preconditions,
          resourceUri: tool.resourceUri,
          challengeStore,
          tokenStore,
          acceptedPreconditionStore,
          onAttestation: (entry) => auditLog.append({ ...entry, signature: "" }),
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
