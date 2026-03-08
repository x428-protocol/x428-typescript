import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { buildAttestation } from "../../src/core/attestation.js";
import { verifyPayloadSignature, base64urlEncode } from "../../src/core/signing.js";
import type { PreconditionChallenge, AttestationObject } from "../../src/core/types.js";

describe("buildAttestation", () => {
  // Deterministic test seed
  const privateKey = new Uint8Array(32).fill(0);
  privateKey[0] = 1;
  const publicKey = ed25519.getPublicKey(privateKey);

  const challenge: PreconditionChallenge = {
    x428Version: 1,
    preconditions: [
      {
        id: "tos-0-abcd1234",
        type: "tos",
        allowedAttestationMethods: ["self"],
        tosVersion: "1.0",
        documentUrl: "https://example.com/tos",
        documentHash: "sha256-abc123",
      },
    ],
    resource: "https://example.com/api/data",
    challenge: "a".repeat(64),
    expiresAt: "2099-01-01T00:00:00.000Z",
  };

  const attestations: AttestationObject[] = [
    {
      preconditionId: "tos-0-abcd1234",
      type: "tos",
      method: "self",
      documentHash: "sha256-abc123",
      confirmedAt: "2025-06-01T00:00:00.000Z",
    },
  ];

  it("produces a payload with all required fields", () => {
    const payload = buildAttestation(challenge, "did:key:z6Mktest", privateKey, attestations);

    expect(payload.x428Version).toBe(1);
    expect(payload.challenge).toBe(challenge.challenge);
    expect(payload.resource).toBe(challenge.resource);
    expect(payload.operatorId).toBe("did:key:z6Mktest");
    expect(payload.attestations).toEqual(attestations);
    expect(typeof payload.signature).toBe("string");
    expect(payload.signature.length).toBeGreaterThan(0);
  });

  it("produces a valid signature verifiable with the corresponding public key", () => {
    const payload = buildAttestation(challenge, "did:key:z6Mktest", privateKey, attestations);

    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: base64urlEncode(publicKey),
    };

    const valid = verifyPayloadSignature(
      payload as unknown as Record<string, unknown>,
      jwk,
    );
    expect(valid).toBe(true);
  });

  it("signature fails verification with a different key", () => {
    const payload = buildAttestation(challenge, "did:key:z6Mktest", privateKey, attestations);

    const otherKey = new Uint8Array(32).fill(0);
    otherKey[0] = 2;
    const otherPublicKey = ed25519.getPublicKey(otherKey);

    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: base64urlEncode(otherPublicKey),
    };

    const valid = verifyPayloadSignature(
      payload as unknown as Record<string, unknown>,
      jwk,
    );
    expect(valid).toBe(false);
  });
});
