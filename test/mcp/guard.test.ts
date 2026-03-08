import { describe, it, expect, vi } from "vitest";
import { x428Guard } from "../../src/mcp/guard.js";
import type { McpServerLike, McpToolExtra } from "../../src/mcp/guard.js";

function mockServer(responses: Array<{ action: string; content?: Record<string, unknown> }>): McpServerLike {
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

describe("x428Guard", () => {
  it("elicits TOS acceptance and passes through on confirm", async () => {
    const server = mockServer([{ action: "accept", content: { accept: true } }]);
    const innerHandler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "Tool result" }],
    });
    const guarded = x428Guard(
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
    const server = mockServer([{ action: "accept", content: { confirm: true } }]);
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428Guard(
      {
        server,
        preconditions: [{ type: "age", minimumAge: 21 }],
      },
      innerHandler,
    );

    const extra = mockExtra("session-2");
    await guarded({}, extra);
    const call = (server.elicitInput as any).mock.calls[0][0];
    expect(call.message).toContain("21");
    expect(innerHandler).toHaveBeenCalledOnce();
  });

  it("returns error when user declines", async () => {
    const server = mockServer([{ action: "decline" }]);
    const innerHandler = vi.fn();
    const guarded = x428Guard(
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

    const extra = mockExtra("session-3");
    const result: any = await guarded({}, extra);
    expect(innerHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("declined");
  });

  it("caches token per session and skips elicitation on second call", async () => {
    const server = mockServer([
      { action: "accept", content: { accept: true } },
      { action: "accept", content: { accept: true } },
    ]);
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428Guard(
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
    expect(server.elicitInput).toHaveBeenCalledOnce(); // cached second time
    expect(innerHandler).toHaveBeenCalledTimes(2);
  });

  it("does not share token cache across sessions", async () => {
    const server = mockServer([
      { action: "accept", content: { accept: true } },
      { action: "accept", content: { accept: true } },
    ]);
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428Guard(
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

    // Both sessions should be elicited independently
    expect(server.elicitInput).toHaveBeenCalledTimes(2);
  });

  it("handles TOS + AGE multi-precondition in single elicitation", async () => {
    // The guard combines all preconditions into a single form with confirm_<id> keys.
    // Mock server accepts and returns all fields as true (keyed dynamically).
    const server: McpServerLike = {
      elicitInput: vi.fn(async (params) => {
        // Accept all fields in the requestedSchema
        const schema = params.requestedSchema as { required?: string[] };
        const content: Record<string, unknown> = {};
        for (const key of schema.required ?? []) {
          content[key] = true;
        }
        return { action: "accept", content };
      }),
    };
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428Guard(
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

    const extra = mockExtra("session-5");
    await guarded({}, extra);
    // Single combined elicitation call
    expect(server.elicitInput).toHaveBeenCalledTimes(1);
    expect(innerHandler).toHaveBeenCalledOnce();
  });
});
