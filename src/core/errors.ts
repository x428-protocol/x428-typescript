/**
 * x428 error codes and error class.
 *
 * Error codes are defined in spec Section 6.6.
 */

/** All error code strings defined by the x428 spec (Section 6.6). */
export type X428ErrorCode =
  | "unsupported_version"
  | "unsupported_type"
  | "malformed_payload"
  | "challenge_expired"
  | "challenge_mismatch"
  | "resource_mismatch"
  | "nonce_replayed"
  | "invalid_signature"
  | "unresolvable_operator"
  | "missing_attestation"
  | "document_hash_mismatch"
  | "vc_issuer_not_accepted"
  | "vc_verification_failed"
  | "method_not_accepted"
  | "token_expired"
  | "token_scope_mismatch";

/**
 * Structured error for x428 protocol failures.
 *
 * Carries a machine-readable `code` (from the spec's error table) and a
 * human-readable `detail` string. Serializes to the JSON shape the spec
 * requires in HTTP 428 error responses.
 */
export class X428Error extends Error {
  readonly code: X428ErrorCode;
  readonly detail: string;

  constructor(code: X428ErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = "X428Error";
    this.code = code;
    this.detail = detail;
  }

  /** Produce the JSON body shape mandated by spec Section 6.6. */
  toJSON(): { error: X428ErrorCode; detail: string } {
    return { error: this.code, detail: this.detail };
  }
}
