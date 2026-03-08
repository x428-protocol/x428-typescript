import { describe, it, expect } from "vitest";
import { X428Error } from "../../src/core/errors.js";

describe("X428Error", () => {
  it("constructs with code and detail", () => {
    const err = new X428Error("challenge_expired", "Nonce has expired");
    expect(err.code).toBe("challenge_expired");
    expect(err.detail).toBe("Nonce has expired");
    expect(err.name).toBe("X428Error");
  });

  it("serializes to JSON", () => {
    const err = new X428Error("invalid_signature", "Sig bad");
    expect(err.toJSON()).toEqual({ error: "invalid_signature", detail: "Sig bad" });
  });
});
