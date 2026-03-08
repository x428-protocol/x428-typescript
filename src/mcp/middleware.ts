import { x428Guard } from "./guard.js";
import type { X428Config, McpServerWithInit } from "./guard.js";

/**
 * Gate all tools on an MCP server behind x428 precondition attestation.
 *
 * Intercepts `mcpServer.tool()` calls and wraps each with `x428Guard`,
 * which auto-detects MCP Apps support for rich inline UI or falls back
 * to elicitation dialogs.
 *
 * @param mcpServer - The McpServer instance (from `@modelcontextprotocol/sdk`)
 * @param config - x428 precondition configuration
 */
export function x428Protect(
  mcpServer: McpServerWithInit,
  config: Omit<X428Config, "server"> & { server?: X428Config["server"] },
): void {
  const fullConfig: X428Config = {
    ...config,
    server: config.server ?? (mcpServer.server as any),
  };

  const originalTool = mcpServer.tool.bind(mcpServer);

  mcpServer.tool = (...toolArgs: any[]) => {
    // MCP SDK tool() signature variants:
    //   tool(name, schema, handler)
    //   tool(name, description, schema, handler)
    const name = toolArgs[0] as string;
    const handlerIndex = toolArgs.length - 1;
    const handler = toolArgs[handlerIndex];

    if (typeof handler !== "function") {
      return originalTool(...toolArgs);
    }

    // Extract description and inputSchema based on argument count
    let description: string | undefined;
    let inputSchema: Record<string, unknown> | undefined;

    if (toolArgs.length === 4) {
      description = toolArgs[1];
      inputSchema = toolArgs[2];
    } else if (toolArgs.length === 3) {
      inputSchema = toolArgs[1];
    }

    // Delegate to x428Guard which handles auto-detection
    x428Guard(mcpServer, fullConfig, name, { description, inputSchema }, handler);
  };
}
