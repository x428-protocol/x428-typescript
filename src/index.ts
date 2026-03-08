// Core types
export type {
  PreconditionType, AttestationMethod,
  PreconditionObject, TosPrecondition, AgePrecondition, IdentityPrecondition,
  PreconditionChallenge,
  AttestationObject, AttestationPayload, AttestationToken,
  DidDocument, DidVerificationMethod,
} from "./core/types.js";

// Errors
export { X428Error } from "./core/errors.js";
export type { X428ErrorCode } from "./core/errors.js";

// Core functions
export { jcsCanonical, jcsCanonicalBytes, jcsCanonicalHex } from "./core/jcs.js";
export { signPayload, verifyPayloadSignature } from "./core/signing.js";
export { generateChallenge } from "./core/challenge.js";
export type { PreconditionConfig, ChallengeOptions } from "./core/challenge.js";
export { buildAttestation } from "./core/attestation.js";
export { verifyAttestation } from "./core/verify.js";
export { generateToken, validateToken, scopeMatches } from "./core/token.js";
export { determinePayloadForm } from "./core/routing.js";

// DID resolution
export type { DidResolver } from "./core/did.js";
export { DidKeyResolver, StaticDidResolver } from "./core/did.js";

// Nonce store
export type { NonceStore } from "./core/nonce.js";
export { InMemoryNonceStore } from "./core/nonce.js";

// MCP adapter
export { x428Guard } from "./mcp/guard.js";
export type { X428Config } from "./mcp/guard.js";
export { buildElicitation } from "./mcp/elicitation.js";
