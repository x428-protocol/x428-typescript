import type { X428Config } from "./guard.js";
import { x428Guard } from "./guard.js";

/**
 * Gate all tools on an MCP server behind x428 precondition attestation.
 *
 * Wraps the server's `tool` method so every tool registered after this call
 * is automatically guarded with the provided x428 config.
 */
export function x428Protect(server: any, config: X428Config): void {
  const originalTool = server.tool.bind(server);

  server.tool = (...toolArgs: any[]) => {
    // MCP SDK tool() signature: tool(name, schema, handler) or tool(name, description, schema, handler)
    // The handler is always the last argument
    const handlerIndex = toolArgs.length - 1;
    const originalHandler = toolArgs[handlerIndex];

    if (typeof originalHandler === "function") {
      toolArgs[handlerIndex] = x428Guard(config, originalHandler);
    }

    return originalTool(...toolArgs);
  };
}
