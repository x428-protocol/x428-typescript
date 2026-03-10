import { describe, it, expect, vi } from "vitest";
import { x428Guard, x428GuardElicitation } from "../src/guard.js";
import type { McpServerLike, McpToolExtra, McpServerWithInit, ChallengeStore, TokenStore } from "../src/guard.js";

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

/** Create a mock McpServer with registerTool support. */
function createMockMcpServer(): McpServerWithInit & {
  _tools: Map<string, { handler: Function; config?: any }>;
  _resources: Map<string, Function>;
  callTool(name: string, args: any, extra: McpToolExtra): Promise<any>;
  /** Simulate an initialize request to populate rawExtensions (call after x428Guard). */
  simulateInitialize(extensions?: Record<string, unknown>): Promise<void>;
} {
  const tools = new Map<string, { handler: Function; config?: any }>();
  const resources = new Map<string, Function>();

  const server: any = {
    getClientCapabilities: vi.fn().mockReturnValue({
      extensions: { "io.modelcontextprotocol/ui": { mimeTypes: ["text/html;profile=mcp-app"] } },
    }),
    // Minimal _onrequest stub so ensureExtensionsCapture can intercept it
    _onrequest: vi.fn(async (_request: any, _extra: any) => {}),
    oninitialized: null as (() => void) | null,
    elicitInput: vi.fn(async (params: any) => {
      const schema = params.requestedSchema as { required?: string[] };
      const content: Record<string, unknown> = {};
      for (const key of schema.required ?? []) {
        content[key] = true;
      }
      content.accept = true;
      content.confirm = true;
      return { action: "accept", content };
    }),
  };

  return {
    server,
    tool: vi.fn((...args: any[]) => {
      const name = args[0];
      const handler = args[args.length - 1];
      tools.set(name, { handler });
    }),
    registerTool: vi.fn((name: string, config: any, handler: Function) => {
      tools.set(name, { handler, config });
    }),
    resource: vi.fn((_name: string, uri: string, _config: any, handler: Function) => {
      resources.set(uri, handler);
    }),
    registerResource: vi.fn((_name: string, uri: string, _config: any, handler: Function) => {
      resources.set(uri, handler);
    }),
    _tools: tools,
    _resources: resources,
    async callTool(name: string, args: any, extra: McpToolExtra) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`Tool ${name} not registered`);
      return tool.handler(args, extra);
    },
    async simulateInitialize(extensions?: Record<string, unknown>) {
      // Trigger the wrapped _onrequest with a fake initialize request
      // so ensureExtensionsCapture populates rawExtensions.
      const ext = extensions ?? { "io.modelcontextprotocol/ui": { mimeTypes: ["text/html;profile=mcp-app"] } };
      await server._onrequest(
        { method: "initialize", params: { capabilities: { extensions: ext } } },
        {},
      );
    },
  };
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
  it("registers tool with _meta.ui via registerTool", () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", { description: "Search" }, handler);

    expect(mcpServer._tools.has("search")).toBe(true);
    // Registered via registerTool with _meta
    expect(mcpServer.registerTool).toHaveBeenCalled();
    const config = mcpServer._tools.get("search")?.config;
    expect(config?._meta?.ui?.resourceUri).toBe("ui://x428/guard");
    expect(config?._meta?.["ui/resourceUri"]).toBe("ui://x428/guard");
  });

  it("registers ui resource and x428-attest tool eagerly", () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    // Both registered eagerly (not deferred to first call)
    expect(mcpServer._tools.has("x428-attest")).toBe(true);
    expect(mcpServer._resources.has("ui://x428/guard")).toBe(true);
  });

  it("returns structuredContent on first call", async () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    await mcpServer.simulateInitialize();
    const result = await mcpServer.callTool("search", { query: "test" }, mockExtra());
    expect(result.structuredContent.x428Status).toBe("pending");
    expect(result.structuredContent.toolName).toBe("search");
    expect(result.structuredContent.toolArgs).toEqual({ query: "test" });
    expect(result._meta.ui.resourceUri).toBe("ui://x428/guard");
    expect(handler).not.toHaveBeenCalled();
  });

  it("x428-attest caches token, re-call on same session executes handler", async () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    await mcpServer.simulateInitialize();
    const extra = mockExtra("s1");
    // First call → pending
    const pending = await mcpServer.callTool("search", { q: "hi" }, extra);
    const challengeId = pending.structuredContent.challengeId;
    expect(challengeId).toBeDefined();
    // Accept attestation → caches token by sessionId
    const attestResult = await mcpServer.callTool("x428-attest", { challengeId, accepted: true }, extra);
    expect(attestResult.content[0].text).toContain("accepted");
    expect(handler).not.toHaveBeenCalled();
    // Re-call on same session → token found, handler executes
    const result = await mcpServer.callTool("search", { q: "hi" }, extra);
    expect(handler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("result");
  });

  it("x428-attest returns error when declined", async () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn();

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    await mcpServer.simulateInitialize();
    const extra = mockExtra("s2");
    const pending = await mcpServer.callTool("search", {}, extra);
    const challengeId = pending.structuredContent.challengeId;
    const result = await mcpServer.callTool("x428-attest", { challengeId, accepted: false }, extra);
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("declined");
  });
});

// ---------------------------------------------------------------------------
// x428Guard — always returns Apps path regardless of capabilities
// ---------------------------------------------------------------------------

describe("x428Guard — capability-independent behavior", () => {
  it("returns structuredContent even when client has elicitation capability", async () => {
    const mcpServer = createMockMcpServer();
    mcpServer.server.getClientCapabilities = vi.fn().mockReturnValue({ elicitation: {} });
    const handler = vi.fn();

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    const result = await mcpServer.callTool("search", { q: "test" }, mockExtra("e1"));
    // Always returns structuredContent (Apps path), never uses elicitation
    expect(result.structuredContent.x428Status).toBe("pending");
    expect(handler).not.toHaveBeenCalled();
    expect(mcpServer.server.elicitInput).not.toHaveBeenCalled();
  });

  it("returns structuredContent when client has no capabilities at all", async () => {
    const mcpServer = createMockMcpServer();
    mcpServer.server.getClientCapabilities = vi.fn().mockReturnValue({});
    const handler = vi.fn();

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    const result = await mcpServer.callTool("search", {}, mockExtra("e2"));
    // Still returns structuredContent — host decides whether to render App
    expect(result.structuredContent.x428Status).toBe("pending");
    expect(handler).not.toHaveBeenCalled();
  });

  it("cross-session: attest on AppBridge, re-call on same AppBridge session", async () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "search", {}, handler);

    // Model session calls tool → gets challengeId
    const pending = await mcpServer.callTool("search", { q: "hi" }, mockExtra("model-session"));
    const challengeId = pending.structuredContent.challengeId;

    // AppBridge session attests (different sessionId, finds challenge by UUID)
    const appExtra = mockExtra("appbridge-session");
    const attestResult = await mcpServer.callTool("x428-attest", { challengeId, accepted: true }, appExtra);
    expect(attestResult.content[0].text).toContain("accepted");

    // AppBridge re-calls tool (same session as attest) → token found
    const result = await mcpServer.callTool("search", { q: "hi" }, appExtra);
    expect(handler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("result");
  });
});

// ---------------------------------------------------------------------------
// ensureExtensionsCapture timing (McpAgent lifecycle)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Pluggable challenge and token stores
// ---------------------------------------------------------------------------

describe("x428Guard — pluggable stores", () => {
  it("uses custom challengeStore and tokenStore when provided", async () => {
    const challenges = new Map<string, any>();
    const tokens = new Map<string, any>();

    const customChallengeStore: ChallengeStore = {
      get: vi.fn((id) => challenges.get(id) ?? null),
      set: vi.fn((id, challenge) => { challenges.set(id, challenge); }),
      delete: vi.fn((id) => { challenges.delete(id); }),
    };

    const customTokenStore: TokenStore = {
      get: vi.fn((key) => tokens.get(key) ?? null),
      set: vi.fn((key, token) => { tokens.set(key, token); }),
    };

    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
      challengeStore: customChallengeStore,
      tokenStore: customTokenStore,
    }, "search", {}, handler);

    await mcpServer.simulateInitialize();
    const extra = mockExtra("ps1");

    // First call → pending, should store challenge in custom store
    const pending = await mcpServer.callTool("search", { q: "hi" }, extra);
    const challengeId = pending.structuredContent.challengeId;
    expect(customChallengeStore.set).toHaveBeenCalledWith(challengeId, expect.any(Object));
    expect(challenges.has(challengeId)).toBe(true);

    // Accept attestation → should use custom stores
    const attestResult = await mcpServer.callTool("x428-attest", { challengeId, accepted: true }, extra);
    expect(attestResult.content[0].text).toContain("accepted");
    expect(customChallengeStore.get).toHaveBeenCalledWith(challengeId);
    expect(customChallengeStore.delete).toHaveBeenCalledWith(challengeId);
    expect(customTokenStore.set).toHaveBeenCalled();

    // Re-call → should find token in custom store
    const result = await mcpServer.callTool("search", { q: "hi" }, extra);
    expect(customTokenStore.get).toHaveBeenCalled();
    expect(handler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("result");
  });

  it("falls back to default stores when none provided", async () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });

    // No challengeStore or tokenStore — should use defaults (module-level Maps)
    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
    }, "fallback-tool", {}, handler);

    await mcpServer.simulateInitialize();
    const extra = mockExtra("ps2");

    const pending = await mcpServer.callTool("fallback-tool", {}, extra);
    const challengeId = pending.structuredContent.challengeId;
    const attestResult = await mcpServer.callTool("x428-attest", { challengeId, accepted: true }, extra);
    expect(attestResult.content[0].text).toContain("accepted");

    const result = await mcpServer.callTool("fallback-tool", {}, extra);
    expect(handler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("result");
  });
});

// ---------------------------------------------------------------------------
// onAttestation audit callback
// ---------------------------------------------------------------------------

describe("x428Guard — onAttestation callback", () => {
  it("fires onAttestation with correct data after successful attestation", async () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "result" }] });
    const onAttestation = vi.fn();

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
      onAttestation,
    }, "audited-tool", {}, handler);

    await mcpServer.simulateInitialize();
    const extra = mockExtra("audit-session");

    // First call → pending
    const pending = await mcpServer.callTool("audited-tool", {}, extra);
    const challengeId = pending.structuredContent.challengeId;
    expect(onAttestation).not.toHaveBeenCalled();

    // Accept attestation → should fire callback
    await mcpServer.callTool("x428-attest", { challengeId, accepted: true }, extra);
    expect(onAttestation).toHaveBeenCalledOnce();

    const entry = onAttestation.mock.calls[0][0];
    expect(entry.challengeId).toBe(challengeId);
    expect(entry.sessionId).toBe("audit-session");
    expect(entry.operatorDid).toMatch(/^did:key:/);
    expect(Array.isArray(entry.attestations)).toBe(true);
    expect(entry.attestations.length).toBe(1);
    expect(entry.attestations[0].type).toBe("tos");
  });

  it("does not fire onAttestation when attestation is declined", async () => {
    const mcpServer = createMockMcpServer();
    const handler = vi.fn();
    const onAttestation = vi.fn();

    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" },
      ],
      onAttestation,
    }, "declined-tool", {}, handler);

    await mcpServer.simulateInitialize();
    const extra = mockExtra("decline-session");

    const pending = await mcpServer.callTool("declined-tool", {}, extra);
    const challengeId = pending.structuredContent.challengeId;

    await mcpServer.callTool("x428-attest", { challengeId, accepted: false }, extra);
    expect(onAttestation).not.toHaveBeenCalled();
  });
});

describe("ensureExtensionsCapture timing", () => {
  it("captures extensions even when _onrequest is set after patching", async () => {
    // Simulate McpAgent lifecycle: init() before connect()
    const mockLowLevelServer = {
      // _onrequest is NOT set yet (connect() hasn't been called)
      getClientCapabilities: () => null,
    } as any;
    const mcpServer = {
      server: mockLowLevelServer,
      tool: vi.fn(),
    } as any;

    // Call x428Guard — this triggers ensureExtensionsCapture
    // At this point _onrequest is undefined
    x428Guard(mcpServer, {
      preconditions: [
        { type: "tos", documentUrl: "https://example.com/tos", tosVersion: "1.0", documentHash: "sha256-abc" },
      ],
    }, "search", { description: "Search" }, async () => ({ content: [{ type: "text", text: "ok" }] }));

    // NOW simulate connect() setting _onrequest (after our patch)
    const fakeOnRequest = vi.fn().mockResolvedValue(undefined);
    mockLowLevelServer._onrequest = fakeOnRequest;

    // Call _onrequest with an initialize message containing extensions.
    // With the fix, the defineProperty setter wraps fakeOnRequest, so
    // reading _onrequest back gives us the wrapper (not fakeOnRequest itself).
    // The wrapper should intercept the extensions AND delegate to fakeOnRequest.
    const initRequest = {
      method: "initialize",
      params: { capabilities: { extensions: { "x428": { version: "0.1" } } } },
    };
    await mockLowLevelServer._onrequest(initRequest, {});

    // The original handler should still be called (delegation works)
    expect(fakeOnRequest).toHaveBeenCalled();

    // The wrapper should have intercepted the extensions and stored them.
    // Without the fix, _onrequest IS fakeOnRequest (no wrapper), so
    // the extensions are never captured. We verify by checking that
    // _onrequest is NOT the same reference as fakeOnRequest (it's wrapped).
    expect(mockLowLevelServer._onrequest).not.toBe(fakeOnRequest);
  });
});
