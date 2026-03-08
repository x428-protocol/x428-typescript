import { describe, it, expect } from "vitest";
import { jcsCanonical, jcsCanonicalHex } from "../../src/core/jcs.js";
import vectors from "@x428-vectors/jcs.json";

describe("JCS canonicalization", () => {
  for (const vector of vectors) {
    describe(vector.description, () => {
      it("produces correct canonical JSON", () => {
        const result = jcsCanonical(vector.input as Record<string, unknown>);
        expect(result).toBe(vector.expected.canonicalJson);
      });

      it("produces correct canonical hex", () => {
        const result = jcsCanonicalHex(vector.input as Record<string, unknown>);
        expect(result).toBe(vector.expected.canonicalHex);
      });
    });
  }
});
