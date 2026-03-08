import { describe, it, expect } from "vitest";
import { scopeMatches } from "../../src/core/token.js";
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
