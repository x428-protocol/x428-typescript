import { describe, it, expect, vi } from "vitest";
import { x428Guard, x428GuardElicitation } from "../../src/mcp/guard.js";
import type { McpServerLike, McpToolExtra, McpServerWithInit } from "../../src/mcp/guard.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockElicitServer(
  responses: Array<{ action: string; content?: Record<string, unknown> }>,
): McpServerLike {
  let callIndex = 0;
  return {
    elicitInput: vi.fn(async () => responses[callIndex++] ?? { action: "decline" }),
  };
}

function mockExtra(sessionId: string = "session-1"): McpToolExtra {
  return {
    sessionId,
    signal: new AbortController().signal,
    requestId: "req-1",
  };
}

/** Create a mock McpServer. */
function createMockMcpServer(supportsApps = false): McpServerWithInit & {
  _tools: Map<string, { handler: Function }>;
  _resources: Map<string, Function>;
  callTool(name: string, args: any, extra: McpToolExtra): Promise<any>;
} {
  const tools = new Map<string, { handler: Function }>();
  const resources = new Map<string, Function>();

  const server: any = {
    // After Zod parsing, extensions are stripped — so getClientCapabilities never has them
    getClientCapabilities: vi.fn().mockReturnValue({}),
    oninitialized: null as (() => void) | null,
    elicitInput: vi.fn(async (params: any) => {
      // Auto-accept all fields
      const schema = params.requestedSchema as { required?: string[] };
      const content: Record<string, unknown> = {};
      for (const key of schema.required ?? []) {
        content[key] = true;
      }
      content.accept = true;
      content.confirm = true;
      return { action: "accept", content };
    }),
    // Provide _onrequest so the interceptor can wrap it
    _onrequest: vi.fn(),
  };

  const mcpServer = {
    server,
    tool: vi.fn((...args: any[]) => {
      const name = args[0];
      const handler = args[args.length - 1];
      tools.set(name, { handler });
    }),
    registerTool: vi.fn((name: string, _config: any, handler: Function) => {
      tools.set(name, { handler });
    }),
    resource: vi.fn((_name: string, uri: string, _config: any, handler: Function) => {
      resources.set(uri, handler);
    }),
    _tools: tools,
    _resources: resources,
    async callTool(name: string, args: any, extra: McpToolExtra) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`Tool ${name} not registered`);
      return tool.handler(args, extra);
    },
    /**
     * Simulate the initialize message arriving (with raw extensions before Zod stripping).
     * Call this after x428Guard to trigger the interceptor.
     */
    simulateInitialize() {
      if (supportsApps && server._onrequest) {
        // The interceptor wraps _onrequest; call the wrapper with a fake initialize request
        server._onrequest({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-03-26",
            capabilities: {
              extensions: {
                "io.modelcontextprotocol/ui": {
                  mimeTypes: ["text/html;profile=mcp-app"],
                },
              },
            },
            clientInfo: { name: "test", version: "1.0" },
          },
        }, {});
      }
    },
  };
  return mcpServer;
}

// ---------------------------------------------------------------------------
// x428GuardElicitation (backward-compat wrapper)
// ---------------------------------------------------------------------------

describe("x428GuardElicitation", () => {
  it("elicits TOS acceptance and passes through on confirm", async () => {
    const server = mockElicitServer([{ action: "accept", content: { accept: true } }]);
    const innerHandler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "Tool result" }],
    });
    const guarded = x428GuardElicitation(
      {
        server,
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
          },
        ],
      },
      innerHandler,
    );

    const extra = mockExtra();
    const result = await guarded({}, extra);
    expect(server.elicitInput).toHaveBeenCalledOnce();
    const call = (server.elicitInput as any).mock.calls[0][0];
    expect(call.message).toContain("Terms of Service");
    expect(innerHandler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("Tool result");
  });

  it("elicits AGE confirmation", async () => {
    const server = mockElicitServer([{ action: "accept", content: { confirm: true } }]);
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428GuardElicitation(
      {
        server,
        preconditions: [{ type: "age", minimumAge: 21 }],
      },
      innerHandler,
    );

    await guarded({}, mockExtra("session-2"));
    const call = (server.elicitInput as any).mock.calls[0][0];
    expect(call.message).toContain("21");
    expect(innerHandler).toHaveBeenCalledOnce();
  });

  it("returns error when user declines", async () => {
    const server = mockElicitServer([{ action: "decline" }]);
    const innerHandler = vi.fn();
    const guarded = x428GuardElicitation(
      {
        server,
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
          },
        ],
      },
      innerHandler,
    );

    const result: any = await guarded({}, mockExtra("session-3"));
    expect(innerHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("declined");
  });

  it("caches token per session and skips elicitation on second call", async () => {
    const server = mockElicitServer([
      { action: "accept", content: { accept: true } },
      { action: "accept", content: { accept: true } },
    ]);
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428GuardElicitation(
      {
        server,
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
          },
        ],
      },
      innerHandler,
    );

    const extra = mockExtra("session-4");
    await guarded({}, extra);
    await guarded({}, extra);
    expect(server.elicitInput).toHaveBeenCalledOnce();
    expect(innerHandler).toHaveBeenCalledTimes(2);
  });

  it("does not share token cache across sessions", async () => {
    const server = mockElicitServer([
      { action: "accept", content: { accept: true } },
      { action: "accept", content: { accept: true } },
    ]);
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428GuardElicitation(
      {
        server,
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
          },
        ],
      },
      innerHandler,
    );

    await guarded({}, mockExtra("session-A"));
    await guarded({}, mockExtra("session-B"));
    expect(server.elicitInput).toHaveBeenCalledTimes(2);
  });

  it("handles TOS + AGE multi-precondition in single elicitation", async () => {
    const server: McpServerLike = {
      elicitInput: vi.fn(async (params) => {
        const schema = params.requestedSchema as { required?: string[] };
        const content: Record<string, unknown> = {};
        for (const key of schema.required ?? []) {
          content[key] = true;
        }
        return { action: "accept", content };
      }),
    };
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428GuardElicitation(
      {
        server,
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
          },
          { type: "age", minimumAge: 18 },
        ],
      },
      innerHandler,
    );

    await guarded({}, mockExtra("session-5"));
    expect(server.elicitInput).toHaveBeenCalledTimes(1);
    expect(innerHandler).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// x428Guard — MCP Apps mode
// ---------------------------------------------------------------------------

describe("x428Guard — MCP Apps mode", () => {
  it("registers tool immediately", () => {
    const mcpServer = createMockMcpServer(true);
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", { description: "Search" }, handler);

    // Tool registered immediately (not deferred)
    expect(mcpServer._tools.has("search")).toBe(true);
  });

  it("returns pending structuredContent on first call when apps supported", async () => {
    const mcpServer = createMockMcpServer(true);
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    // Simulate initialize message arriving (interceptor captures raw extensions)
    mcpServer.simulateInitialize();

    const result = await mcpServer.callTool("search", { query: "test" }, mockExtra());
    expect(result.structuredContent.x428Status).toBe("pending");
    expect(result.structuredContent.toolName).toBe("search");
    expect(result.structuredContent.toolArgs).toEqual({ query: "test" });
    expect(handler).not.toHaveBeenCalled();
  });

  it("registers x428/attest and resource lazily on first call", async () => {
    const mcpServer = createMockMcpServer(true);
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    // Before first call — only search registered
    expect(mcpServer._tools.has("x428/attest")).toBe(false);

    // Simulate initialize message arriving
    mcpServer.simulateInitialize();

    // First call triggers lazy registration
    await mcpServer.callTool("search", {}, mockExtra());

    expect(mcpServer._tools.has("x428/attest")).toBe(true);
    expect(mcpServer._resources.has("ui://x428/guard")).toBe(true);
  });

  it("x428/attest caches token, second call executes handler", async () => {
    const mcpServer = createMockMcpServer(true);
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    // Simulate initialize message arriving
    mcpServer.simulateInitialize();

    const extra = mockExtra("s1");
    // First call → pending
    await mcpServer.callTool("search", {}, extra);
    // Accept attestation
    await mcpServer.callTool("x428/attest", { challengeId: "s1", accepted: true }, extra);
    // Second call → handler executes
    const result = await mcpServer.callTool("search", { q: "hi" }, extra);
    expect(handler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("result");
  });
});

// ---------------------------------------------------------------------------
// x428Guard — Elicitation fallback mode
// ---------------------------------------------------------------------------

describe("x428Guard — Elicitation fallback", () => {
  it("falls back to elicitation when client does not support apps", async () => {
    const mcpServer = createMockMcpServer(false);
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    // Tool registered immediately
    expect(mcpServer._tools.has("search")).toBe(true);

    // Call tool — should use elicitation via server.elicitInput
    const result = await mcpServer.callTool("search", { query: "test" }, mockExtra("e1"));
    expect(mcpServer.server.elicitInput).toHaveBeenCalled();
    expect(handler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("result");

    // Should NOT register x428/attest
    expect(mcpServer._tools.has("x428/attest")).toBe(false);
  });

  it("caches token and skips elicitation on second call", async () => {
    const mcpServer = createMockMcpServer(false);
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    const extra = mockExtra("e2");
    await mcpServer.callTool("search", {}, extra);
    await mcpServer.callTool("search", {}, extra);
    expect(mcpServer.server.elicitInput).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledTimes(2);
  });
});
