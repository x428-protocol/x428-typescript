import { describe, it, expect } from "vitest";
import { DidKeyResolver, StaticDidResolver } from "../../src/core/did.js";
import type { DidDocument } from "../../src/core/types.js";

const VALID_OPERATOR_DID =
  "did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";

describe("DidKeyResolver", () => {
  const resolver = new DidKeyResolver();

  it("resolves a did:key to a DID document with assertionMethod", async () => {
    const doc = await resolver.resolve(VALID_OPERATOR_DID);
    expect(doc).not.toBeNull();
    expect(doc!.id).toBe(VALID_OPERATOR_DID);
    expect(doc!.verificationMethod).toHaveLength(1);
    expect(doc!.verificationMethod![0]!.type).toBe("JsonWebKey2020");
    expect(doc!.verificationMethod![0]!.controller).toBe(VALID_OPERATOR_DID);
    expect(doc!.verificationMethod![0]!.publicKeyJwk).toBeDefined();
    expect((doc!.verificationMethod![0]!.publicKeyJwk as any).kty).toBe("OKP");
    expect((doc!.verificationMethod![0]!.publicKeyJwk as any).crv).toBe(
      "Ed25519",
    );
    expect((doc!.verificationMethod![0]!.publicKeyJwk as any).x).toBe(
      "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
    );
    expect(doc!.assertionMethod).toHaveLength(1);
    expect(doc!.assertionMethod![0]).toBe(
      `${VALID_OPERATOR_DID}#z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7`,
    );
  });

  it("returns null for non-did:key DID", async () => {
    const doc = await resolver.resolve("did:web:example.com");
    expect(doc).toBeNull();
  });

  it("returns null for malformed did:key", async () => {
    const doc = await resolver.resolve("did:key:z123invalid");
    expect(doc).toBeNull();
  });
});

describe("StaticDidResolver", () => {
  const mockDoc: DidDocument = {
    id: "did:web:example.com",
    verificationMethod: [
      {
        id: "did:web:example.com#key-1",
        type: "Ed25519VerificationKey2020",
        controller: "did:web:example.com",
      },
    ],
    assertionMethod: ["did:web:example.com#key-1"],
  };

  const resolver = new StaticDidResolver({
    "did:web:example.com": mockDoc,
  });

  it("returns document from map", async () => {
    const doc = await resolver.resolve("did:web:example.com");
    expect(doc).toEqual(mockDoc);
  });

  it("returns null for unknown DID", async () => {
    const doc = await resolver.resolve("did:web:unknown.com");
    expect(doc).toBeNull();
  });
});
