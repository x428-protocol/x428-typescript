/**
 * x428 attestation verification — 10-step server-side verification.
 *
 * Implements the normative verification order from the spec:
 * 1. Version check
 * 2. Well-formed check
 * 3. Nonce match
 * 4. Resource match
 * 5. Expiry
 * 6. Replay check
 * 7. DID resolution
 * 8. Signature verification
 * 9. Attestation completeness
 * 10. Per-type validation
 */

import type {
  AttestationPayload,
  AttestationToken,
  DidDocument,
  DidVerificationMethod,
  PreconditionChallenge,
} from "./types.js";
import { X428Error } from "./errors.js";
import type { DidResolver } from "./did.js";
import { base58btcDecode } from "./did.js";
import type { NonceStore } from "./nonce.js";
import { verifyPayloadSignature, base64urlDecode } from "./signing.js";
import { generateToken } from "./token.js";

/**
 * Verify a VC's DataIntegrityProof by resolving the issuer DID and
 * checking the proof signature over the VC content (with proof removed).
 */
async function verifyVcProof(
  vc: Record<string, unknown>,
  resolver: DidResolver,
): Promise<boolean> {
  const proof = vc.proof as Record<string, unknown> | undefined;
  if (!proof?.proofValue) return false;

  // Extract the issuer DID
  const issuer = vc.issuer as string | undefined;
  if (!issuer) return false;

  // Resolve issuer DID
  const issuerDoc = await resolver.resolve(issuer);
  if (!issuerDoc) return false;

  const issuerKeyBytes = extractAssertionKey(issuerDoc);
  if (!issuerKeyBytes) return false;

  // Verify: construct a payload-like object from the VC (without proof)
  // and use the proofValue as the "signature"
  const { proof: _proof, ...vcWithoutProof } = vc;
  const verifyObj = { ...vcWithoutProof, signature: proof.proofValue };
  return verifyPayloadSignature(verifyObj, issuerKeyBytes);
}

const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Extract raw Ed25519 public key bytes from a verification method.
 * Supports publicKeyJwk, publicKeyBase58, and publicKeyMultibase.
 */
function extractPublicKeyBytes(method: DidVerificationMethod): Uint8Array | null {
  if (method.publicKeyJwk) {
    const jwk = method.publicKeyJwk as { x?: string };
    if (!jwk.x) return null;
    return base64urlDecode(jwk.x);
  }

  if (method.publicKeyBase58) {
    return base58btcDecode(method.publicKeyBase58);
  }

  if (method.publicKeyMultibase) {
    const encoded = method.publicKeyMultibase;
    if (!encoded.startsWith("z")) return null;
    const decoded = base58btcDecode(encoded.slice(1));
    // Strip multicodec prefix if present
    if (
      decoded.length >= 2 &&
      decoded[0] === ED25519_MULTICODEC_PREFIX[0] &&
      decoded[1] === ED25519_MULTICODEC_PREFIX[1]
    ) {
      return decoded.slice(2);
    }
    return decoded;
  }

  return null;
}

/**
 * Extract the first assertionMethod public key bytes from a DID document.
 */
function extractAssertionKey(didDoc: DidDocument): Uint8Array | null {
  if (!didDoc.assertionMethod?.length) return null;
  const methodId = didDoc.assertionMethod[0];
  if (!methodId || !didDoc.verificationMethod) return null;

  const id = typeof methodId === "string" ? methodId : methodId.id;
  const method = didDoc.verificationMethod.find((vm) => vm.id === id);
  if (!method) return null;

  return extractPublicKeyBytes(method);
}

/**
 * Verify an attestation payload against its challenge following the
 * spec-mandated 10-step verification order.
 *
 * Returns an AttestationToken on success or an X428Error on failure.
 */
export async function verifyAttestation(
  challenge: PreconditionChallenge,
  payload: AttestationPayload,
  resolver: DidResolver,
  nonceStore: NonceStore,
  currentTime?: Date,
  tokenTtlSeconds?: number,
): Promise<AttestationToken | X428Error> {
  const now = currentTime ?? new Date();

  // Step 1: Version check
  if (payload.x428Version !== challenge.x428Version) {
    return new X428Error(
      "unsupported_version",
      `Payload x428Version ${payload.x428Version} does not match challenge version ${challenge.x428Version}`,
    );
  }

  // Step 2: Well-formed check
  const p = payload as unknown as Record<string, unknown>;
  if (
    !Array.isArray(p.attestations) ||
    !p.challenge ||
    !p.resource ||
    !p.operatorId ||
    !p.signature
  ) {
    return new X428Error(
      "malformed_payload",
      "Payload is missing required fields or attestations is not an array",
    );
  }

  // Step 3: Nonce match
  if (payload.challenge !== challenge.challenge) {
    return new X428Error(
      "challenge_mismatch",
      "Payload challenge nonce does not match issued challenge",
    );
  }

  // Step 4: Resource match
  if (payload.resource !== challenge.resource) {
    return new X428Error(
      "resource_mismatch",
      "Payload resource does not match challenge resource",
    );
  }

  // Step 5: Expiry
  if (now >= new Date(challenge.expiresAt)) {
    return new X428Error(
      "challenge_expired",
      "Challenge has expired",
    );
  }

  // Step 6: Replay check
  if (nonceStore.has(challenge.challenge)) {
    return new X428Error(
      "nonce_replayed",
      "Nonce has already been consumed",
    );
  }

  // Step 7: DID resolution
  const didDoc = await resolver.resolve(payload.operatorId);
  if (!didDoc) {
    return new X428Error(
      "unresolvable_operator",
      `Cannot resolve DID: ${payload.operatorId}`,
    );
  }

  // Step 8: Signature verification
  const publicKeyBytes = extractAssertionKey(didDoc);
  if (!publicKeyBytes) {
    return new X428Error(
      "invalid_signature",
      "No assertionMethod key found in DID document",
    );
  }

  const sigValid = verifyPayloadSignature(
    payload as unknown as Record<string, unknown>,
    publicKeyBytes,
  );
  if (!sigValid) {
    return new X428Error(
      "invalid_signature",
      "Payload signature verification failed",
    );
  }

  // Step 9: Attestation completeness
  const attestationsByPreconditionId = new Map<string, Record<string, unknown>>();
  for (const att of payload.attestations) {
    attestationsByPreconditionId.set(att.preconditionId, att as unknown as Record<string, unknown>);
  }

  for (const precondition of challenge.preconditions) {
    if (!attestationsByPreconditionId.has(precondition.id)) {
      return new X428Error(
        "missing_attestation",
        `No attestation found for precondition ${precondition.id}`,
      );
    }
  }

  // Step 10: Per-type validation
  for (const precondition of challenge.preconditions) {
    const att = attestationsByPreconditionId.get(precondition.id)!;
    const preconditionAny = precondition as unknown as Record<string, unknown>;
    const type = preconditionAny.type as string;
    const method = att.method as string;
    const allowedMethods = preconditionAny.allowedAttestationMethods as string[];

    // Check method is in allowedAttestationMethods
    if (!allowedMethods.includes(method)) {
      return new X428Error(
        "method_not_accepted",
        `Method "${method}" is not in allowedAttestationMethods for precondition ${precondition.id}`,
      );
    }

    // For identity: vc/gov methods are reserved in v0.1
    if (type === "identity" && (method === "vc" || method === "gov")) {
      return new X428Error(
        "method_not_accepted",
        `Method "${method}" is reserved for identity preconditions in v0.1`,
      );
    }

    // Unknown precondition type
    if (type !== "tos" && type !== "age" && type !== "identity") {
      return new X428Error(
        "unsupported_type",
        `Unknown precondition type: ${type}`,
      );
    }

    // TOS-specific validation
    if (type === "tos") {
      if (method === "self") {
        // Check documentHash matches
        if (att.documentHash !== preconditionAny.documentHash) {
          return new X428Error(
            "document_hash_mismatch",
            "Attestation documentHash does not match challenge documentHash",
          );
        }
      } else if (method === "vc") {
        const vc = att.vc as Record<string, unknown> | undefined;
        if (!vc) {
          return new X428Error(
            "vc_verification_failed",
            "VC attestation missing vc field",
          );
        }
        const issuer = vc.issuer as string;
        const acceptedIssuers = preconditionAny.acceptedVcIssuers as string[] | undefined;
        if (acceptedIssuers && !acceptedIssuers.includes(issuer)) {
          return new X428Error(
            "vc_issuer_not_accepted",
            `VC issuer ${issuer} is not in acceptedVcIssuers`,
          );
        }
        // Check proof exists
        const proof = vc.proof as Record<string, unknown> | undefined;
        if (!proof) {
          return new X428Error(
            "vc_verification_failed",
            "VC is missing proof",
          );
        }
        // Check documentHash in credentialSubject matches
        const subject = vc.credentialSubject as Record<string, unknown> | undefined;
        if (subject) {
          const vcDocHash = subject.documentHash as string | undefined;
          if (vcDocHash && vcDocHash !== preconditionAny.documentHash) {
            return new X428Error(
              "document_hash_mismatch",
              "VC credentialSubject.documentHash does not match challenge documentHash",
            );
          }
        }
        // Verify VC proof signature
        const vcProofValid = await verifyVcProof(vc, resolver);
        if (!vcProofValid) {
          return new X428Error(
            "vc_verification_failed",
            "VC proof signature verification failed",
          );
        }
      }
    }

    // AGE-specific validation
    if (type === "age") {
      if (method === "vc") {
        const vc = att.vc as Record<string, unknown> | undefined;
        if (!vc) {
          return new X428Error(
            "vc_verification_failed",
            "VC attestation missing vc field",
          );
        }
        // Check no birthdate in credentialSubject (privacy violation)
        const subject = vc.credentialSubject as Record<string, unknown> | undefined;
        if (subject && "birthdate" in subject) {
          return new X428Error(
            "vc_verification_failed",
            "AGE VC credentialSubject must not contain birthdate",
          );
        }
        // Check issuer in acceptedVcIssuers
        const issuer = vc.issuer as string;
        const acceptedIssuers = preconditionAny.acceptedVcIssuers as string[] | undefined;
        if (acceptedIssuers && !acceptedIssuers.includes(issuer)) {
          return new X428Error(
            "vc_issuer_not_accepted",
            `VC issuer ${issuer} is not in acceptedVcIssuers`,
          );
        }
        // Check proof exists and verify
        const proof = vc.proof as Record<string, unknown> | undefined;
        if (!proof) {
          return new X428Error(
            "vc_verification_failed",
            "VC is missing proof",
          );
        }
        const vcProofValid = await verifyVcProof(vc, resolver);
        if (!vcProofValid) {
          return new X428Error(
            "vc_verification_failed",
            "VC proof signature verification failed",
          );
        }
      }
    }
  }

  // Success: add nonce to store and return token
  nonceStore.add(challenge.challenge);
  return generateToken(challenge.resource, tokenTtlSeconds ?? 3600);
}
