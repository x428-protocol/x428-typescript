import { ed25519 } from "@noble/curves/ed25519.js";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes: Uint8Array): string {
  let num = 0n;
  for (const byte of bytes) num = num * 256n + BigInt(byte);
  let encoded = "";
  while (num > 0n) {
    encoded = BASE58_ALPHABET[Number(num % 58n)] + encoded;
    num = num / 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) encoded = "1" + encoded;
    else break;
  }
  return encoded;
}

export interface EphemeralDid {
  did: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate an ephemeral Ed25519 keypair and derive a did:key URI. */
export function createEphemeralDid(): EphemeralDid {
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  const publicKey = ed25519.getPublicKey(privateKey);
  const multicodecBytes = new Uint8Array(2 + publicKey.length);
  multicodecBytes[0] = 0xed;
  multicodecBytes[1] = 0x01;
  multicodecBytes.set(publicKey, 2);
  const did = `did:key:z${base58btcEncode(multicodecBytes)}`;
  return { did, privateKey, publicKey };
}
