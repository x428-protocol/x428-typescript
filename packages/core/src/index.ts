// Core types
export type {
  PreconditionType, AttestationMethod,
  PreconditionObject, TosPrecondition, AgePrecondition, IdentityPrecondition,
  PreconditionChallenge,
  AttestationObject, AttestationPayload, AttestationToken,
  DidDocument, DidVerificationMethod,
} from "./types.js";

// Errors
export { X428Error } from "./errors.js";
export type { X428ErrorCode } from "./errors.js";

// Core functions
export { jcsCanonical, jcsCanonicalBytes, jcsCanonicalHex } from "./jcs.js";
export { signPayload, verifyPayloadSignature } from "./signing.js";
export { generateChallenge } from "./challenge.js";
export type {
  PreconditionConfig,
  TosPreconditionConfig,
  AgePreconditionConfig,
  IdentityPreconditionConfig,
  ChallengeOptions,
} from "./challenge.js";
export { buildAttestation } from "./attestation.js";
export { verifyAttestation } from "./verify.js";
export { generateToken, validateToken, scopeMatches } from "./token.js";
export { determinePayloadForm } from "./routing.js";

// DID resolution
export type { DidResolver } from "./did.js";
export { DidKeyResolver, StaticDidResolver } from "./did.js";

// Nonce store
export type { NonceStore } from "./nonce.js";
export { InMemoryNonceStore } from "./nonce.js";
