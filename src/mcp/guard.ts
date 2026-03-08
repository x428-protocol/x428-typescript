import type { AttestationToken, AttestationObject } from "../core/types.js";
import { generateChallenge, type PreconditionConfig } from "../core/challenge.js";
import { buildAttestation } from "../core/attestation.js";
import { verifyAttestation } from "../core/verify.js";
import { X428Error } from "../core/errors.js";
import type { DidResolver } from "../core/did.js";
import { DidKeyResolver } from "../core/did.js";
import type { NonceStore } from "../core/nonce.js";
import { InMemoryNonceStore } from "../core/nonce.js";
import { buildElicitation } from "./elicitation.js";
import { ed25519 } from "@noble/curves/ed25519.js";

export interface X428Config {
  preconditions: PreconditionConfig[];
  resourceUri?: string;
  tokenTtl?: number;
  didResolver?: DidResolver;
  nonceStore?: NonceStore;
}

export function x428Guard<TArgs, TResult>(
  config: X428Config,
  handler: (args: TArgs, ctx: any) => Promise<TResult>,
): (args: TArgs, ctx: any) => Promise<TResult> {
  const tokenTtl = config.tokenTtl ?? 3600;
  // Per-session token cache: sessionId → token
  const tokenCache = new Map<string, AttestationToken>();
  const resolver = config.didResolver ?? new DidKeyResolver();
  const nonceStore = config.nonceStore ?? new InMemoryNonceStore();

  // Generate an ephemeral keypair for self-attestation within the guard
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  const publicKey = ed25519.getPublicKey(privateKey);

  // Build a did:key from the ephemeral public key
  const multicodecBytes = new Uint8Array(2 + publicKey.length);
  multicodecBytes[0] = 0xed;
  multicodecBytes[1] = 0x01;
  multicodecBytes.set(publicKey, 2);

  // Base58btc encode for did:key
  const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (const byte of multicodecBytes) {
    num = num * 256n + BigInt(byte);
  }
  let encoded = "";
  while (num > 0n) {
    encoded = BASE58_ALPHABET[Number(num % 58n)] + encoded;
    num = num / 58n;
  }
  for (const byte of multicodecBytes) {
    if (byte === 0) encoded = "1" + encoded;
    else break;
  }
  const operatorDid = `did:key:z${encoded}`;

  return async (args: TArgs, ctx: any) => {
    const resourceUri = config.resourceUri ?? `x428://mcp/${ctx?.toolName ?? "unknown"}`;
    const sessionId = ctx?.sessionId ?? ctx?.mcpReq?.sessionId ?? "_default";
    const cacheKey = `${sessionId}:${resourceUri}`;

    // Check cached token
    const cached = tokenCache.get(cacheKey);
    if (cached && new Date(cached.expiresAt) > new Date()) {
      return handler(args, ctx);
    }

    // Generate challenge
    const challenge = generateChallenge(config.preconditions, resourceUri, { ttlSeconds: 300 });

    // Elicit user confirmation for each precondition
    const attestations: AttestationObject[] = [];

    for (const precondition of challenge.preconditions) {
      const elicitReq = buildElicitation(precondition);
      const result = await ctx.mcpReq.elicitInput(elicitReq);

      if (result.action !== "accept") {
        return {
          content: [{ type: "text", text: `x428: User declined ${precondition.type} precondition.` }],
          isError: true,
        } as unknown as TResult;
      }

      const confirmed = result.content?.accept ?? result.content?.confirm;
      if (!confirmed) {
        return {
          content: [{ type: "text", text: `x428: User did not confirm ${precondition.type} precondition.` }],
          isError: true,
        } as unknown as TResult;
      }

      const now = new Date().toISOString();
      if (precondition.type === "tos") {
        attestations.push({
          preconditionId: precondition.id,
          type: "tos",
          method: "self",
          documentHash: precondition.documentHash,
          confirmedAt: now,
        });
      } else if (precondition.type === "age") {
        attestations.push({
          preconditionId: precondition.id,
          type: "age",
          method: "self",
          minimumAge: precondition.minimumAge,
          confirmedAt: now,
        });
      } else if (precondition.type === "identity") {
        attestations.push({
          preconditionId: precondition.id,
          type: "identity",
          method: "self",
          confirmedAt: now,
        });
      }
    }

    // Build attestation through the core pipeline
    const payload = buildAttestation(challenge, operatorDid, privateKey, attestations);

    // Verify through the core pipeline
    const verifyResult = await verifyAttestation(
      challenge,
      payload,
      resolver,
      nonceStore,
      undefined,
      tokenTtl,
    );

    if (verifyResult instanceof X428Error) {
      return {
        content: [{ type: "text", text: `x428: Attestation verification failed: ${verifyResult.detail}` }],
        isError: true,
      } as unknown as TResult;
    }

    // Cache the token keyed by session
    tokenCache.set(cacheKey, verifyResult);

    return handler(args, ctx);
  };
}
