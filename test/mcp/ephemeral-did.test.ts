import { describe, it, expect } from "vitest";
import { createEphemeralDid } from "../../src/mcp/ephemeral-did.js";

describe("createEphemeralDid", () => {
  it("returns a did:key and keypair", () => {
    const { did, privateKey, publicKey } = createEphemeralDid();
    expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(32);
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
  });

  it("generates unique DIDs on each call", () => {
    const a = createEphemeralDid();
    const b = createEphemeralDid();
    expect(a.did).not.toBe(b.did);
  });
});
