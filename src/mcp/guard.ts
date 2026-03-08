import type { AttestationToken, AttestationObject, PreconditionObject } from "../core/types.js";
import { generateChallenge, type PreconditionConfig } from "../core/challenge.js";
import { buildAttestation } from "../core/attestation.js";
import { verifyAttestation } from "../core/verify.js";
import { X428Error } from "../core/errors.js";
import type { DidResolver } from "../core/did.js";
import { DidKeyResolver } from "../core/did.js";
import type { NonceStore } from "../core/nonce.js";
import { InMemoryNonceStore } from "../core/nonce.js";
import { buildCombinedElicitation } from "./elicitation.js";
import { createEphemeralDid } from "./ephemeral-did.js";

/**
 * Minimal interface for the MCP server object.
 * Matches `McpServer.server` from `@modelcontextprotocol/sdk`.
 */
export interface McpServerLike {
  elicitInput(params: {
    mode: string;
    message: string;
    requestedSchema: Record<string, unknown>;
  }, options?: { requestId?: string | number }): Promise<{
    action: string;
    content?: Record<string, unknown>;
  }>;
}

/**
 * Minimal interface for the `extra` parameter passed to MCP tool callbacks.
 * Matches `RequestHandlerExtra` from `@modelcontextprotocol/sdk`.
 */
export interface McpToolExtra {
  sessionId?: string;
  signal: AbortSignal;
  requestId: string | number;
  [key: string]: unknown;
}

export interface X428Config {
  preconditions: PreconditionConfig[];
  server: McpServerLike;
  resourceUri?: string;
  tokenTtl?: number;
  didResolver?: DidResolver;
  nonceStore?: NonceStore;
}

export function x428Guard<TArgs, TResult>(
  config: X428Config,
  handler: (args: TArgs, extra: McpToolExtra) => Promise<TResult>,
): (args: TArgs, extra: McpToolExtra) => Promise<TResult> {
  const tokenTtl = config.tokenTtl ?? 3600;
  // Per-session token cache: cacheKey → token
  const tokenCache = new Map<string, AttestationToken>();
  const resolver = config.didResolver ?? new DidKeyResolver();
  const nonceStore = config.nonceStore ?? new InMemoryNonceStore();

  // Generate an ephemeral keypair for self-attestation within the guard
  const { did: operatorDid, privateKey } = createEphemeralDid();

  return async (args: TArgs, extra: McpToolExtra) => {
    const resourceUri = config.resourceUri ?? `x428://mcp/tool`;
    const sessionId = extra.sessionId ?? "_default";
    const cacheKey = `${sessionId}:${resourceUri}`;

    // Check cached token
    const cached = tokenCache.get(cacheKey);
    if (cached && new Date(cached.expiresAt) > new Date()) {
      return handler(args, extra);
    }

    // Generate challenge
    const challenge = generateChallenge(config.preconditions, resourceUri, { ttlSeconds: 300 });
    console.error(`[x428] Generated challenge with ${challenge.preconditions.length} preconditions`);

    // Elicit user confirmation for all preconditions in a single form
    // (MCP clients may not support multiple sequential elicitations)
    const preconditions = challenge.preconditions as PreconditionObject[];
    const elicitReq = buildCombinedElicitation(preconditions);
    console.error(`[x428] Eliciting ${preconditions.length} precondition(s) in single form`);

    let elicitResult: { action: string; content?: Record<string, unknown> };
    try {
      elicitResult = await config.server.elicitInput(elicitReq, { requestId: extra.requestId });
    } catch (err) {
      console.error(`[x428] elicitInput threw:`, err);
      return {
        content: [{ type: "text", text: `x428: Elicitation failed: ${err}` }],
        isError: true,
      } as unknown as TResult;
    }

    console.error(`[x428] Elicitation result: ${JSON.stringify(elicitResult)}`);

    if (elicitResult.action !== "accept") {
      return {
        content: [{ type: "text", text: `x428: User declined precondition(s).` }],
        isError: true,
      } as unknown as TResult;
    }

    // Verify each precondition was confirmed
    const attestations: AttestationObject[] = [];
    for (const precondition of preconditions) {
      // For single-precondition forms, check legacy keys too
      const fieldKey = `confirm_${precondition.id}`;
      const confirmed = elicitResult.content?.[fieldKey]
        ?? (preconditions.length === 1 && (elicitResult.content?.accept ?? elicitResult.content?.confirm));

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

    console.error(`[x428] All ${attestations.length} preconditions confirmed, building attestation`);

    // Build attestation through the core pipeline
    let payload;
    try {
      payload = buildAttestation(challenge, operatorDid, privateKey, attestations);
      console.error(`[x428] Attestation built successfully`);
    } catch (err) {
      console.error(`[x428] buildAttestation threw:`, err);
      return {
        content: [{ type: "text", text: `x428: Failed to build attestation: ${err}` }],
        isError: true,
      } as unknown as TResult;
    }

    // Verify through the core pipeline
    let verifyResult;
    try {
      verifyResult = await verifyAttestation(
        challenge,
        payload,
        resolver,
        nonceStore,
        undefined,
        tokenTtl,
      );
      console.error(`[x428] Verification result: ${verifyResult instanceof X428Error ? `ERROR: ${verifyResult.detail}` : "OK"}`);
    } catch (err) {
      console.error(`[x428] verifyAttestation threw:`, err);
      return {
        content: [{ type: "text", text: `x428: Verification threw: ${err}` }],
        isError: true,
      } as unknown as TResult;
    }

    if (verifyResult instanceof X428Error) {
      return {
        content: [{ type: "text", text: `x428: Attestation verification failed: ${verifyResult.detail}` }],
        isError: true,
      } as unknown as TResult;
    }

    // Cache the token keyed by session
    tokenCache.set(cacheKey, verifyResult);
    console.error(`[x428] Token cached, proceeding to handler`);

    return handler(args, extra);
  };
}
