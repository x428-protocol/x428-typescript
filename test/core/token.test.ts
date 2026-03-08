import { describe, it, expect } from "vitest";
import { scopeMatches, generateToken, validateToken } from "../../src/core/token.js";
import { X428Error } from "../../src/core/errors.js";
import { InMemoryNonceStore } from "../../src/core/nonce.js";
import vectors from "../vectors/scope.json";

interface ScopeVector {
  description: string;
  category: string;
  input: {
    tokenScope: string;
    requestedResource: string;
  };
  expected: {
    matches: boolean;
  };
}

describe("scopeMatches — conformance vectors", () => {
  for (const vector of vectors as ScopeVector[]) {
    it(vector.description, () => {
      const result = scopeMatches(
        vector.input.tokenScope,
        vector.input.requestedResource,
      );
      expect(result).toBe(vector.expected.matches);
    });
  }
});

describe("validateToken", () => {
  it("returns true for valid token", () => {
    const token = generateToken("https://example.com/api", 3600);
    const result = validateToken(token, "https://example.com/api");
    expect(result).toBe(true);
  });

  it("returns token_expired error for expired token", () => {
    const token = generateToken("https://example.com/api", 3600);
    const future = new Date(Date.now() + 7200 * 1000);
    const result = validateToken(token, "https://example.com/api", future);
    expect(result).toBeInstanceOf(X428Error);
    expect((result as X428Error).code).toBe("token_expired");
  });

  it("returns token_scope_mismatch error for wrong scope", () => {
    const token = generateToken("https://example.com/api", 3600);
    const result = validateToken(token, "https://other.com/api");
    expect(result).toBeInstanceOf(X428Error);
    expect((result as X428Error).code).toBe("token_scope_mismatch");
  });
});

describe("InMemoryNonceStore", () => {
  it("tracks nonces correctly", () => {
    const store = new InMemoryNonceStore();
    const nonce = "abc123";

    expect(store.has(nonce)).toBe(false);
    store.add(nonce);
    expect(store.has(nonce)).toBe(true);
    expect(store.has("other")).toBe(false);
  });
});
