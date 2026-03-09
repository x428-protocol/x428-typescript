/**
 * Token scope matching and token generation/validation.
 *
 * Scope matching follows spec Section 6.4:
 * - Strip query string and fragment from requestedResource before matching
 * - Exact match: identical URIs
 * - Prefix wildcard: scope ends with "/*", match prefix, remainder must not
 *   contain "/" (single segment only)
 */

import type { AttestationToken } from "./types.js";
import { X428Error } from "./errors.js";

/**
 * Strip query string and fragment from a URI.
 */
function stripQueryAndFragment(uri: string): string {
  // Remove fragment first, then query string
  const hashIndex = uri.indexOf("#");
  if (hashIndex !== -1) {
    uri = uri.slice(0, hashIndex);
  }
  const queryIndex = uri.indexOf("?");
  if (queryIndex !== -1) {
    uri = uri.slice(0, queryIndex);
  }
  return uri;
}

/**
 * Check whether a token scope covers a requested resource URI.
 *
 * Per spec Section 6.4:
 * 1. Strip query string and fragment from requestedResource
 * 2. Exact match: identical URIs → true
 * 3. Prefix wildcard: scope ends with "/*", match prefix, then remainder
 *    must not contain "/" (single segment only)
 */
export function scopeMatches(
  tokenScope: string,
  requestedResource: string,
): boolean {
  const resource = stripQueryAndFragment(requestedResource);

  // Exact match
  if (tokenScope === resource) return true;

  // Prefix wildcard
  if (tokenScope.endsWith("/*")) {
    const prefix = tokenScope.slice(0, -1); // keep the trailing "/"
    if (resource.startsWith(prefix)) {
      const remainder = resource.slice(prefix.length);
      // remainder must be non-empty and must not contain "/"
      return remainder.length > 0 && !remainder.includes("/");
    }
  }

  return false;
}

/**
 * Generate an attestation token for a given resource scope.
 */
export function generateToken(
  resourceUri: string,
  ttlSeconds: number,
): AttestationToken {
  // Generate a random opaque token
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const token = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const expiresAt = new Date(
    Date.now() + ttlSeconds * 1000,
  ).toISOString();

  return {
    token,
    expiresAt,
    scope: resourceUri,
  };
}

/**
 * Validate a token against a requested URI and check expiry.
 *
 * Returns true if valid, or an X428Error with the specific failure reason.
 */
export function validateToken(
  token: AttestationToken,
  requestedUri: string,
  currentTime?: Date,
): true | X428Error {
  const now = currentTime ?? new Date();
  const expiry = new Date(token.expiresAt);

  if (now >= expiry) {
    return new X428Error("token_expired", "Attestation token has expired");
  }

  if (!scopeMatches(token.scope, requestedUri)) {
    return new X428Error("token_scope_mismatch", `Token scope "${token.scope}" does not cover "${requestedUri}"`);
  }

  return true;
}
