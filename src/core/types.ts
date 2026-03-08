/**
 * x428 Precondition Attestation Protocol — Core Data Types
 *
 * All types correspond to the structures defined in x428 spec Section 5.
 */

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/** Precondition types defined in v0.1 (Section 5.2–5.4). */
export type PreconditionType = "tos" | "age" | "identity";

/**
 * Attestation methods.
 * - "self": operator DID signature (v0.1)
 * - "vc": W3C Verifiable Credential (v0.1 for tos/age; reserved for identity)
 * - "gov": government-attested identity (reserved, not valid in v0.1)
 */
export type AttestationMethod = "self" | "vc" | "gov";

// ---------------------------------------------------------------------------
// PreconditionObjects (Section 5.2–5.4)
// ---------------------------------------------------------------------------

/** Fields common to every PreconditionObject. */
export interface PreconditionBase {
  /** Server-assigned stable identifier, unique within the challenge. */
  id: string;
  /** Precondition type discriminator. */
  type: PreconditionType;
  /** Permitted attestation methods. */
  allowedAttestationMethods: AttestationMethod[];
  /** Human-readable hint for UI contexts. */
  uiHint?: string;
}

/** Section 5.2 — TOS precondition. */
export interface TosPrecondition extends PreconditionBase {
  type: "tos";
  /** Operator-defined version string for the ToS document revision. */
  tosVersion: string;
  /** Canonical URL of the Terms of Service document. */
  documentUrl: string;
  /** SHA-256 hash of the document content, prefixed "sha256-", lowercase hex. */
  documentHash: string;
}

/** Section 5.3 — AGE precondition. */
export interface AgePrecondition extends PreconditionBase {
  type: "age";
  /** Minimum age in whole years required. */
  minimumAge: number;
  /** DID URIs of accepted VC issuers. Required if "vc" is in allowedAttestationMethods. */
  acceptedVcIssuers?: string[];
}

/** Section 5.4 — IDENTITY precondition. Self-attestation only in v0.1. */
export interface IdentityPrecondition extends PreconditionBase {
  type: "identity";
  /** Reserved for future VC tier. MUST NOT be present in v0.1. */
  acceptedVcIssuers?: never;
}

/** Discriminated union of all precondition objects. */
export type PreconditionObject =
  | TosPrecondition
  | AgePrecondition
  | IdentityPrecondition;

// ---------------------------------------------------------------------------
// PreconditionChallenge (Section 5.1)
// ---------------------------------------------------------------------------

/** The challenge issued by a server (X-428-Required header or challengeEndpoint body). */
export interface PreconditionChallenge {
  /** Wire protocol version. MUST be 1 for v0.1. */
  x428Version: number;
  /** Array of one or more PreconditionObjects. */
  preconditions: PreconditionObject[];
  /** Absolute URI of the protected resource. */
  resource: string;
  /** Cryptographically random nonce, lowercase hex, min 32 bytes (64 hex chars). */
  challenge: string;
  /** ISO 8601 datetime in UTC. Server MUST NOT accept attestations after this time. */
  expiresAt: string;
  /** Absolute URI for POST-based attestation submission (payload > 8 KB). */
  attestationEndpoint?: string;
}

// ---------------------------------------------------------------------------
// AttestationObjects (Section 5.6–5.7)
// ---------------------------------------------------------------------------

/** Fields common to every AttestationObject. */
export interface AttestationBase {
  /** MUST match the id of a PreconditionObject in the challenge. */
  preconditionId: string;
  /** MUST match the type of the referenced PreconditionObject. */
  type: PreconditionType;
  /** Attestation method used. */
  method: AttestationMethod;
}

// --- Self-attested (Section 5.6) ---

/** TOS self-attestation. */
export interface TosSelfAttestation extends AttestationBase {
  type: "tos";
  method: "self";
  /** MUST exactly match the documentHash in the referenced PreconditionObject. */
  documentHash: string;
  /** ISO 8601 datetime in UTC. */
  confirmedAt: string;
}

/** AGE self-attestation. */
export interface AgeSelfAttestation extends AttestationBase {
  type: "age";
  method: "self";
  /** MUST exactly match minimumAge in the referenced PreconditionObject. */
  minimumAge: number;
  /** ISO 8601 datetime in UTC. */
  confirmedAt: string;
}

/** IDENTITY self-attestation. */
export interface IdentitySelfAttestation extends AttestationBase {
  type: "identity";
  method: "self";
  /** ISO 8601 datetime in UTC. */
  confirmedAt: string;
}

// --- VC-attested (Section 5.7) ---

/** TOS VC attestation. */
export interface TosVcAttestation extends AttestationBase {
  type: "tos";
  method: "vc";
  /** W3C VC Data Model 2.0 object. */
  vc: Record<string, unknown>;
}

/** AGE VC attestation. */
export interface AgeVcAttestation extends AttestationBase {
  type: "age";
  method: "vc";
  /** W3C VC Data Model 2.0 object. */
  vc: Record<string, unknown>;
}

/** Discriminated union of all attestation objects. */
export type AttestationObject =
  | TosSelfAttestation
  | AgeSelfAttestation
  | IdentitySelfAttestation
  | TosVcAttestation
  | AgeVcAttestation;

// ---------------------------------------------------------------------------
// AttestationPayload (Section 5.5)
// ---------------------------------------------------------------------------

/** The signed payload sent by the client (X-428-Attestation header or POST body). */
export interface AttestationPayload {
  /** MUST exactly match the challenge's x428Version. */
  x428Version: number;
  /** MUST exactly match the challenge nonce. */
  challenge: string;
  /** MUST exactly match the challenge's resource URI. */
  resource: string;
  /** Resolvable DID URI identifying the operator (did:web or did:key in v0.1). */
  operatorId: string;
  /** One AttestationObject per precondition in the challenge. */
  attestations: AttestationObject[];
  /**
   * Base64url-encoded Ed25519 signature (no padding) over the JCS-canonical
   * form of this object with the signature field excluded.
   */
  signature: string;
}

// ---------------------------------------------------------------------------
// AttestationToken (Section 5.8)
// ---------------------------------------------------------------------------

/** Token issued by the server upon successful attestation. */
export interface AttestationToken {
  /** Opaque token string. Clients MUST treat as opaque. */
  token: string;
  /** ISO 8601 datetime in UTC. Token MUST NOT be accepted after this time. */
  expiresAt: string;
  /** Absolute URI defining the resource scope covered by this token. */
  scope: string;
}

// ---------------------------------------------------------------------------
// DID Document (minimal subset for x428)
// ---------------------------------------------------------------------------

/** A single verification method within a DID document. */
export interface DidVerificationMethod {
  /** Fully-qualified ID of the verification method. */
  id: string;
  /** Verification method type (e.g., "Ed25519VerificationKey2020", "Multikey"). */
  type: string;
  /** The DID that controls this verification method. */
  controller: string;
  /** Base58-encoded public key (Ed25519VerificationKey2020). */
  publicKeyBase58?: string;
  /** Multibase-encoded public key (Multikey). */
  publicKeyMultibase?: string;
  /** JWK public key (JsonWebKey2020). */
  publicKeyJwk?: JsonWebKey;
}

/** Minimal DID document subset relevant to x428 verification. */
export interface DidDocument {
  /** The DID URI this document describes. */
  id: string;
  /** Verification methods declared in this document. */
  verificationMethod?: DidVerificationMethod[];
  /** Verification methods authorized for assertion/attestation. */
  assertionMethod?: (string | DidVerificationMethod)[];
}
