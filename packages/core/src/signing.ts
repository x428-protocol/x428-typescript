import { ed25519 } from "@noble/curves/ed25519.js";
import { jcsCanonicalBytes } from "./jcs.js";

export function base64urlDecode(str: string): Uint8Array {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function signPayload(
  payloadWithoutSig: Record<string, unknown>,
  privateKey: Uint8Array,
): string {
  const message = jcsCanonicalBytes(payloadWithoutSig);
  const signature = ed25519.sign(message, privateKey);
  return base64urlEncode(signature);
}

export function verifyPayloadSignature(
  payload: Record<string, unknown>,
  publicKeyBytes: Uint8Array,
): boolean {
  try {
    const { signature, ...rest } = payload;
    if (typeof signature !== "string") return false;

    const sigBytes = base64urlDecode(signature);
    if (sigBytes.length !== 64) return false;

    const message = jcsCanonicalBytes(rest);

    return ed25519.verify(sigBytes, message, publicKeyBytes);
  } catch {
    return false;
  }
}
