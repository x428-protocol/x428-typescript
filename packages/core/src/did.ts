/**
 * DID resolution for x428.
 *
 * Supports did:key (Ed25519 only) and a static resolver for testing.
 */

import type { DidDocument, DidVerificationMethod } from "./types.js";
import { base64urlEncode } from "./signing.js";

// ---------------------------------------------------------------------------
// Resolver interface
// ---------------------------------------------------------------------------

export interface DidResolver {
  resolve(did: string): Promise<DidDocument | null>;
}

// ---------------------------------------------------------------------------
// Base58btc decoding (Bitcoin alphabet)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btcDecode(encoded: string): Uint8Array {
  if (encoded.length === 0) return new Uint8Array(0);

  // Build reverse lookup
  const indexes = new Map<string, number>();
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    indexes.set(BASE58_ALPHABET[i]!, i);
  }

  // Convert to base-256
  const bytes: number[] = [0];
  for (const char of encoded) {
    const value = indexes.get(char);
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // Count leading '1's → leading zero bytes
  let leadingZeros = 0;
  for (const char of encoded) {
    if (char === "1") leadingZeros++;
    else break;
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  // Leading zeros are already 0 in the Uint8Array
  for (let i = 0; i < bytes.length; i++) {
    result[leadingZeros + i] = bytes[bytes.length - 1 - i]!;
  }
  return result;
}

// ---------------------------------------------------------------------------
// DidKeyResolver — resolves did:key:z... (Ed25519 only)
// ---------------------------------------------------------------------------

const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

export class DidKeyResolver implements DidResolver {
  async resolve(did: string): Promise<DidDocument | null> {
    if (!did.startsWith("did:key:z")) return null;

    try {
      const multibaseEncoded = did.slice("did:key:".length);
      // Strip the 'z' multibase prefix (base58btc)
      const decoded = base58btcDecode(multibaseEncoded.slice(1));

      // Check multicodec prefix 0xed 0x01
      if (
        decoded.length < 2 ||
        decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
        decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
      ) {
        return null;
      }

      // Extract 32-byte public key
      const publicKeyBytes = decoded.slice(2);
      if (publicKeyBytes.length !== 32) return null;

      const keyId = `${did}#${multibaseEncoded}`;

      const verificationMethod: DidVerificationMethod = {
        id: keyId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: base64urlEncode(publicKeyBytes),
        },
      };

      return {
        id: did,
        verificationMethod: [verificationMethod],
        assertionMethod: [keyId],
      };
    } catch {
      return null;
    }
  }
}

// ---------------------------------------------------------------------------
// StaticDidResolver — resolves from a provided map (for testing)
// ---------------------------------------------------------------------------

export class StaticDidResolver implements DidResolver {
  private documents: Record<string, DidDocument>;

  constructor(documents: Record<string, DidDocument>) {
    this.documents = documents;
  }

  async resolve(did: string): Promise<DidDocument | null> {
    return this.documents[did] ?? null;
  }
}
