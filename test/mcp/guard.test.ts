import { describe, it, expect, vi } from "vitest";
import { x428Guard } from "../../src/mcp/guard.js";

describe("x428Guard", () => {
  it("elicits TOS acceptance and passes through on confirm", async () => {
    const innerHandler = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "Tool result" }],
    });
    const guarded = x428Guard(
      {
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
            allowedAttestationMethods: ["self"],
          },
        ],
      },
      innerHandler,
    );

    const mockCtx = {
      toolName: "test-tool",
      mcpReq: {
        elicitInput: vi.fn().mockResolvedValue({ action: "accept", content: { accept: true } }),
      },
    };

    const result = await guarded({}, mockCtx);
    expect(mockCtx.mcpReq.elicitInput).toHaveBeenCalledOnce();
    expect(mockCtx.mcpReq.elicitInput.mock.calls[0][0].message).toContain("Terms of Service");
    expect(innerHandler).toHaveBeenCalledOnce();
    expect(result.content[0].text).toBe("Tool result");
  });

  it("elicits AGE confirmation", async () => {
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428Guard(
      {
        preconditions: [{ type: "age", minimumAge: 21, allowedAttestationMethods: ["self"] }],
      },
      innerHandler,
    );

    const mockCtx = {
      toolName: "age-gated",
      mcpReq: {
        elicitInput: vi.fn().mockResolvedValue({ action: "accept", content: { confirm: true } }),
      },
    };

    await guarded({}, mockCtx);
    expect(mockCtx.mcpReq.elicitInput.mock.calls[0][0].message).toContain("21");
    expect(innerHandler).toHaveBeenCalledOnce();
  });

  it("returns error when user declines", async () => {
    const innerHandler = vi.fn();
    const guarded = x428Guard(
      {
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
            allowedAttestationMethods: ["self"],
          },
        ],
      },
      innerHandler,
    );

    const mockCtx = {
      toolName: "test-tool",
      mcpReq: { elicitInput: vi.fn().mockResolvedValue({ action: "decline" }) },
    };

    const result: any = await guarded({}, mockCtx);
    expect(innerHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("declined");
  });

  it("caches token and skips elicitation on second call", async () => {
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428Guard(
      {
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
            allowedAttestationMethods: ["self"],
          },
        ],
      },
      innerHandler,
    );

    const mockCtx = {
      toolName: "test-tool",
      mcpReq: {
        elicitInput: vi.fn().mockResolvedValue({ action: "accept", content: { accept: true } }),
      },
    };

    await guarded({}, mockCtx);
    await guarded({}, mockCtx);
    expect(mockCtx.mcpReq.elicitInput).toHaveBeenCalledOnce(); // cached second time
    expect(innerHandler).toHaveBeenCalledTimes(2);
  });

  it("handles TOS + AGE multi-precondition", async () => {
    const innerHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "OK" }] });
    const guarded = x428Guard(
      {
        preconditions: [
          {
            type: "tos",
            tosVersion: "1.0",
            documentUrl: "https://example.com/tos",
            documentHash: "sha256-abc",
            allowedAttestationMethods: ["self"],
          },
          { type: "age", minimumAge: 18, allowedAttestationMethods: ["self"] },
        ],
      },
      innerHandler,
    );

    const mockCtx = {
      toolName: "gated-tool",
      mcpReq: {
        elicitInput: vi
          .fn()
          .mockResolvedValueOnce({ action: "accept", content: { accept: true } })
          .mockResolvedValueOnce({ action: "accept", content: { confirm: true } }),
      },
    };

    await guarded({}, mockCtx);
    expect(mockCtx.mcpReq.elicitInput).toHaveBeenCalledTimes(2);
    expect(innerHandler).toHaveBeenCalledOnce();
  });
});
