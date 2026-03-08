import { describe, it, expect } from "vitest";
import { generateChallenge } from "../../src/core/challenge.js";
import type { PreconditionConfig } from "../../src/core/challenge.js";

describe("generateChallenge", () => {
  it("creates a valid challenge with required fields", () => {
    const challenge = generateChallenge(
      [
        {
          type: "tos",
          tosVersion: "1.0",
          documentUrl: "https://example.com/tos",
          documentHash: "sha256-abc123",
        },
      ],
      "https://example.com/api/data",
    );

    expect(challenge.x428Version).toBe(1);
    expect(challenge.resource).toBe("https://example.com/api/data");
    // Nonce must be at least 64 hex chars (32 bytes)
    expect(challenge.challenge).toMatch(/^[0-9a-f]{64,}$/);
    // expiresAt must be a valid ISO 8601 string
    expect(new Date(challenge.expiresAt).toISOString()).toBe(challenge.expiresAt);
    expect(challenge.preconditions).toHaveLength(1);
    expect(challenge.preconditions[0].type).toBe("tos");
  });

  it("defaults allowedAttestationMethods to ['self']", () => {
    const challenge = generateChallenge(
      [{ type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" }],
      "https://example.com/resource",
    );

    expect(challenge.preconditions[0].allowedAttestationMethods).toEqual(["self"]);
  });

  it("assigns unique IDs to each precondition", () => {
    const challenge = generateChallenge(
      [
        {
          type: "tos",
          tosVersion: "1.0",
          documentUrl: "https://example.com/tos",
          documentHash: "sha256-abc123",
        },
        {
          type: "age",
          minimumAge: 18,
        },
        {
          type: "identity",
        },
      ],
      "https://example.com/resource",
    );

    const ids = challenge.preconditions.map((p) => p.id);
    expect(new Set(ids).size).toBe(3);
    // Each ID should start with its type
    expect(ids[0]).toMatch(/^tos-/);
    expect(ids[1]).toMatch(/^age-/);
    expect(ids[2]).toMatch(/^identity-/);
  });

  it("respects custom TTL", () => {
    const before = Date.now();
    const challenge = generateChallenge(
      [{ type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" }],
      "https://example.com/resource",
      { ttlSeconds: 60 },
    );
    const after = Date.now();

    const expiresMs = new Date(challenge.expiresAt).getTime();
    // Should expire roughly 60 seconds from now (within a 2-second tolerance)
    expect(expiresMs).toBeGreaterThanOrEqual(before + 60 * 1000 - 1);
    expect(expiresMs).toBeLessThanOrEqual(after + 60 * 1000 + 1);
  });

  it("includes attestationEndpoint when provided", () => {
    const challenge = generateChallenge(
      [{ type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" }],
      "https://example.com/resource",
      { attestationEndpoint: "https://example.com/attest" },
    );

    expect(challenge.attestationEndpoint).toBe("https://example.com/attest");
  });

  it("throws on empty preconditions array", () => {
    expect(() => generateChallenge([], "https://example.com/resource")).toThrow(
      "At least one precondition is required",
    );
  });

  it("throws when TOS missing tosVersion", () => {
    // @ts-expect-error — testing runtime validation of invalid input
    expect(() => generateChallenge([{ type: "tos", documentUrl: "https://example.com/tos", documentHash: "sha256-abc" }], "https://example.com/resource")).toThrow(
      "TOS requires tosVersion",
    );
  });

  it("throws when TOS missing documentUrl", () => {
    // @ts-expect-error — testing runtime validation of invalid input
    expect(() => generateChallenge([{ type: "tos", tosVersion: "1.0", documentHash: "sha256-abc" }], "https://example.com/resource")).toThrow(
      "TOS requires documentUrl",
    );
  });

  it("throws when TOS missing documentHash", () => {
    // @ts-expect-error — testing runtime validation of invalid input
    expect(() => generateChallenge([{ type: "tos", tosVersion: "1.0", documentUrl: "https://example.com/tos" }], "https://example.com/resource")).toThrow(
      "TOS requires documentHash",
    );
  });

  it("throws when AGE missing minimumAge", () => {
    // @ts-expect-error — testing runtime validation of invalid input
    expect(() => generateChallenge([{ type: "age" }], "https://example.com/resource")).toThrow(
      "AGE requires minimumAge",
    );
  });

  it("accepts valid identity precondition with no extra fields", () => {
    const challenge = generateChallenge(
      [{ type: "identity" }],
      "https://example.com/resource",
    );

    expect(challenge.preconditions[0].type).toBe("identity");
  });
});
