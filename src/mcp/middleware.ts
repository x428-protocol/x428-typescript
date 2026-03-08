import type { X428Config } from "./guard.js";
import { x428Guard } from "./guard.js";

/**
 * Gate all tools on an MCP server behind x428 precondition attestation.
 *
 * Wraps the server's `tool` method so every tool registered after this call
 * is automatically guarded with the provided x428 config.
 *
 * @param mcpServer - The McpServer instance (from `@modelcontextprotocol/sdk`)
 * @param config - x428 configuration. The `server` field will be set automatically
 *   from `mcpServer.server` if not provided.
 */
export function x428Protect(mcpServer: { server: any; tool: (...args: any[]) => any }, config: Omit<X428Config, "server"> & { server?: X428Config["server"] }): void {
  const fullConfig: X428Config = {
    ...config,
    server: config.server ?? mcpServer.server,
  };

  const originalTool = mcpServer.tool.bind(mcpServer);

  mcpServer.tool = (...toolArgs: any[]) => {
    // MCP SDK tool() signature: tool(name, schema, handler) or tool(name, description, schema, handler)
    // The handler is always the last argument
    const handlerIndex = toolArgs.length - 1;
    const originalHandler = toolArgs[handlerIndex];

    if (typeof originalHandler === "function") {
      toolArgs[handlerIndex] = x428Guard(fullConfig, originalHandler);
    }

    return originalTool(...toolArgs);
  };
}
