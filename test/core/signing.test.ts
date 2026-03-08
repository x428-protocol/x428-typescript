import { describe, it, expect } from "vitest";
import { verifyPayloadSignature } from "../../src/core/signing.js";
import vectors from "../vectors/signature.json";

interface SignatureVector {
  description: string;
  category: string;
  input: {
    payload: Record<string, unknown>;
    publicKeyJwk: { kty: string; crv: string; x: string };
  };
  expected: {
    valid: boolean;
  };
}

describe("Ed25519 signing and verification", () => {
  for (const vector of vectors as SignatureVector[]) {
    it(vector.description, () => {
      const { payload, publicKeyJwk } = vector.input;
      const result = verifyPayloadSignature(payload, publicKeyJwk);
      expect(result).toBe(vector.expected.valid);
    });
  }
});
