import { describe, it, expect } from "vitest";
import { verifyAttestation } from "../../src/core/verify.js";
import { StaticDidResolver } from "../../src/core/did.js";
import { InMemoryNonceStore } from "../../src/core/nonce.js";
import { X428Error } from "../../src/core/errors.js";
import type { AttestationToken } from "../../src/core/types.js";

import verifyCommonVectors from "@x428-vectors/verify-common.json";
import verifyTosVectors from "@x428-vectors/verify-tos.json";
import verifyAgeVectors from "@x428-vectors/verify-age.json";
import verifyIdentityVectors from "@x428-vectors/verify-identity.json";
import verifyMultiVectors from "@x428-vectors/verify-multi.json";
import verifySequenceVectors from "@x428-vectors/verify-sequence.json";

function runVerifyVector(vector: any, sharedStore?: InMemoryNonceStore) {
  const {
    challenge,
    attestationPayload,
    didDocument,
    nonceStore,
    currentTime,
    vcIssuerDidDocument,
  } = vector.input;

  const didDocs: Record<string, any> = {};
  if (didDocument) didDocs[didDocument.id] = didDocument;
  if (vcIssuerDidDocument) didDocs[vcIssuerDidDocument.id] = vcIssuerDidDocument;

  const resolver = new StaticDidResolver(didDocs);

  const store = sharedStore ?? new InMemoryNonceStore();
  if (!sharedStore) {
    for (const nonce of nonceStore ?? []) {
      store.add(nonce);
    }
  }

  return verifyAttestation(
    challenge,
    attestationPayload,
    resolver,
    store,
    new Date(currentTime),
  );
}

function assertVectorResult(result: AttestationToken | X428Error, expected: any) {
  if (expected.accept) {
    expect(result).not.toBeInstanceOf(X428Error);
    expect((result as AttestationToken).scope).toBe(expected.tokenScope);
  } else {
    expect(result).toBeInstanceOf(X428Error);
    expect((result as X428Error).code).toBe(expected.errorCode);
  }
}

describe("verify-common vectors", () => {
  for (const vector of verifyCommonVectors) {
    it(vector.description, async () => {
      const result = await runVerifyVector(vector);
      assertVectorResult(result, vector.expected);
    });
  }
});

describe("verify-tos vectors", () => {
  for (const vector of verifyTosVectors) {
    it(vector.description, async () => {
      const result = await runVerifyVector(vector);
      assertVectorResult(result, vector.expected);
    });
  }
});

describe("verify-age vectors", () => {
  for (const vector of verifyAgeVectors) {
    it(vector.description, async () => {
      const result = await runVerifyVector(vector);
      assertVectorResult(result, vector.expected);
    });
  }
});

describe("verify-identity vectors", () => {
  for (const vector of verifyIdentityVectors) {
    it(vector.description, async () => {
      const result = await runVerifyVector(vector);
      assertVectorResult(result, vector.expected);
    });
  }
});

describe("verify-multi vectors", () => {
  for (const vector of verifyMultiVectors) {
    it(vector.description, async () => {
      const result = await runVerifyVector(vector);
      assertVectorResult(result, vector.expected);
    });
  }
});

describe("verify-sequence vectors", () => {
  for (const vector of verifySequenceVectors) {
    it(vector.description, async () => {
      const store = new InMemoryNonceStore();

      for (const step of (vector as any).steps) {
        // For sequence vectors, populate nonce store from step input
        // but use the shared store to carry state across steps
        const {
          challenge,
          attestationPayload,
          didDocument,
          currentTime,
          vcIssuerDidDocument,
        } = step.input;

        const didDocs: Record<string, any> = {};
        if (didDocument) didDocs[didDocument.id] = didDocument;
        if (vcIssuerDidDocument) didDocs[vcIssuerDidDocument.id] = vcIssuerDidDocument;

        const resolver = new StaticDidResolver(didDocs);

        const result = await verifyAttestation(
          challenge,
          attestationPayload,
          resolver,
          store,
          new Date(currentTime),
        );

        assertVectorResult(result, step.expected);
      }
    });
  }
});
