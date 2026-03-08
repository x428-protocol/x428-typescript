import type {
  AttestationToken,
  AttestationObject,
  PreconditionObject,
  PreconditionChallenge,
} from "../core/types.js";
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
import { buildAppHtml } from "./app-ui.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Minimal interface for the low-level MCP Server (McpServer.server).
 */
export interface McpServerLike {
  elicitInput(
    params: { mode: string; message: string; requestedSchema: Record<string, unknown> },
    options?: { requestId?: string | number },
  ): Promise<{ action: string; content?: Record<string, unknown> }>;
}

/** Minimal interface for the `extra` parameter passed to MCP tool callbacks. */
export interface McpToolExtra {
  sessionId?: string;
  signal: AbortSignal;
  requestId: string | number;
  [key: string]: unknown;
}

export interface X428Config {
  preconditions: PreconditionConfig[];
  /** Required for elicitation fallback. Typically `mcpServer.server`. */
  server?: McpServerLike;
  resourceUri?: string;
  tokenTtl?: number;
  didResolver?: DidResolver;
  nonceStore?: NonceStore;
}

/**
 * Minimal McpServer shape accepted by x428Guard.
 * Compatible with `McpServer` from `@modelcontextprotocol/sdk`.
 */
export interface McpServerWithInit {
  server: {
    getClientCapabilities?(): Record<string, unknown> | null | undefined;
    oninitialized?: (() => void) | null;
    elicitInput?(
      params: { mode: string; message: string; requestedSchema: Record<string, unknown> },
      options?: { requestId?: string | number },
    ): Promise<{ action: string; content?: Record<string, unknown> }>;
  };
  tool(...args: any[]): any;
  resource?(...args: any[]): any;
}

// UI resource URI shared by all guarded tools
const UI_RESOURCE_URI = "ui://x428/guard";
const RESOURCE_MIME_TYPE = "text/html;profile=mcp-app";
const EXTENSION_ID = "io.modelcontextprotocol/ui";

// ---------------------------------------------------------------------------
// Shared attestation helpers
// ---------------------------------------------------------------------------

function buildAttestationsFromChallenge(
  challenge: PreconditionChallenge,
): AttestationObject[] {
  const now = new Date().toISOString();
  return (challenge.preconditions as PreconditionObject[]).map((p) => {
    const base = { preconditionId: p.id, method: "self" as const, confirmedAt: now };
    switch (p.type) {
      case "tos":
        return { ...base, type: "tos" as const, documentHash: p.documentHash };
      case "age":
        return { ...base, type: "age" as const, minimumAge: p.minimumAge };
      case "identity":
        return { ...base, type: "identity" as const };
    }
  });
}

async function processAttestation(
  challenge: PreconditionChallenge,
  operatorDid: string,
  privateKey: Uint8Array,
  resolver: DidResolver,
  nonceStore: NonceStore,
  tokenTtl: number,
): Promise<AttestationToken | X428Error> {
  const attestations = buildAttestationsFromChallenge(challenge);
  const payload = buildAttestation(challenge, operatorDid, privateKey, attestations);
  return verifyAttestation(challenge, payload, resolver, nonceStore, undefined, tokenTtl);
}

// Per-server state for MCP Apps mode
interface AppsState {
  supportsApps: boolean | null; // null = not yet detected
  pendingChallenges: Map<string, PreconditionChallenge>;
  attestToolRegistered: boolean;
  resourceRegistered: boolean;
}

const serverAppsState = new WeakMap<McpServerWithInit, AppsState>();

function getAppsState(server: McpServerWithInit): AppsState {
  let state = serverAppsState.get(server);
  if (!state) {
    state = {
      supportsApps: null,
      pendingChallenges: new Map(),
      attestToolRegistered: false,
      resourceRegistered: false,
    };
    serverAppsState.set(server, state);
  }
  return state;
}

function detectAppsSupport(server: McpServerWithInit): boolean {
  const state = getAppsState(server);
  if (state.supportsApps !== null) return state.supportsApps;

  const caps = server.server.getClientCapabilities?.() ?? {};
  const extensions = (caps as any)?.extensions;
  const uiCap = extensions?.[EXTENSION_ID];
  state.supportsApps = !!(uiCap?.mimeTypes?.includes(RESOURCE_MIME_TYPE));
  return state.supportsApps;
}

function ensureAppsInfrastructure(
  server: McpServerWithInit,
  pendingChallenges: Map<string, PreconditionChallenge>,
  operatorDid: string,
  privateKey: Uint8Array,
  resolver: DidResolver,
  nonceStore: NonceStore,
  tokenTtl: number,
  tokenCache: Map<string, AttestationToken>,
  resourceUri: string,
): void {
  const state = getAppsState(server);

  // Register the shared UI resource (once per server)
  if (!state.resourceRegistered && server.resource) {
    state.resourceRegistered = true;
    server.resource(
      "x428-guard-ui",
      UI_RESOURCE_URI,
      { mimeType: RESOURCE_MIME_TYPE },
      async () => ({
        contents: [{ uri: UI_RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: buildAppHtml() }],
      }),
    );
  }

  // Register the hidden x428/attest tool (once per server)
  if (!state.attestToolRegistered) {
    state.attestToolRegistered = true;
    server.tool(
      "x428/attest",
      "x428 attestation endpoint (app-only)",
      { challengeId: { type: "string" }, accepted: { type: "boolean" } },
      async (args: { challengeId: string; accepted: boolean }, extra: McpToolExtra) => {
        const sessionId = extra.sessionId ?? "_default";

        if (!args.accepted) {
          return {
            content: [{ type: "text", text: "x428: User declined preconditions." }],
            isError: true,
          };
        }

        const challenge = state.pendingChallenges.get(args.challengeId ?? sessionId);
        if (!challenge) {
          return {
            content: [{ type: "text", text: "x428: No pending challenge found." }],
            isError: true,
          };
        }

        try {
          const result = await processAttestation(
            challenge, operatorDid, privateKey, resolver, nonceStore, tokenTtl,
          );

          if (result instanceof X428Error) {
            return {
              content: [{ type: "text", text: `x428: Attestation failed: ${result.detail}` }],
              isError: true,
            };
          }

          const cacheKey = `${sessionId}:${resourceUri}`;
          tokenCache.set(cacheKey, result);
          state.pendingChallenges.delete(args.challengeId ?? sessionId);

          return {
            content: [{ type: "text", text: "x428: Attestation accepted. You may now use the tool." }],
          };
        } catch (err) {
          return {
            content: [{ type: "text", text: `x428: Attestation error: ${err}` }],
            isError: true,
          };
        }
      },
    );
  }
}

// ---------------------------------------------------------------------------
// x428Guard — unified guard with MCP Apps auto-detect
// ---------------------------------------------------------------------------

/**
 * Register a single MCP tool with x428 precondition enforcement.
 *
 * Registers the tool immediately. On first call, detects client capabilities:
 * - If MCP Apps supported → returns `structuredContent` with pending status,
 *   registers shared `ui://x428/guard` resource and hidden `x428/attest` tool.
 * - Otherwise → uses `elicitInput()` for confirmation (existing behavior).
 */
export function x428Guard(
  mcpServer: McpServerWithInit,
  config: X428Config,
  toolName: string,
  toolConfig: { description?: string; inputSchema?: Record<string, unknown> },
  handler: (args: any, extra: McpToolExtra) => Promise<any>,
): void {
  const tokenTtl = config.tokenTtl ?? 3600;
  const tokenCache = new Map<string, AttestationToken>();
  const resolver = config.didResolver ?? new DidKeyResolver();
  const nonceStore = config.nonceStore ?? new InMemoryNonceStore();
  const resourceUri = config.resourceUri ?? `x428://mcp/tool/${toolName}`;
  const { did: operatorDid, privateKey } = createEphemeralDid();
  const elicitServer = config.server ?? (mcpServer.server as unknown as McpServerLike);

  function getCachedToken(sessionId: string): AttestationToken | undefined {
    const key = `${sessionId}:${resourceUri}`;
    const cached = tokenCache.get(key);
    if (cached && new Date(cached.expiresAt) > new Date()) return cached;
    return undefined;
  }

  // Register tool immediately so capabilities are advertised
  const toolArgs: any[] = [toolName];
  if (toolConfig.description) toolArgs.push(toolConfig.description);
  if (toolConfig.inputSchema) toolArgs.push(toolConfig.inputSchema);

  toolArgs.push(async (args: any, extra: McpToolExtra) => {
    const sessionId = extra.sessionId ?? "_default";
    const cached = getCachedToken(sessionId);
    if (cached) return handler(args, extra);

    // Lazy capability detection on first uncached call
    const supportsApps = detectAppsSupport(mcpServer);

    if (supportsApps) {
      return handleAppsPath(args, extra, sessionId);
    } else {
      return handleElicitationPath(args, extra, sessionId);
    }
  });

  mcpServer.tool(...toolArgs);

  // --- MCP Apps path ---
  function handleAppsPath(args: any, extra: McpToolExtra, sessionId: string): any {
    const state = getAppsState(mcpServer);

    // Ensure resource + attest tool are registered (lazy, once)
    ensureAppsInfrastructure(
      mcpServer, state.pendingChallenges,
      operatorDid, privateKey, resolver, nonceStore, tokenTtl, tokenCache, resourceUri,
    );

    // Generate challenge and return pending structuredContent
    const challenge = generateChallenge(config.preconditions, resourceUri, { ttlSeconds: 300 });
    state.pendingChallenges.set(sessionId, challenge);

    return {
      content: [{ type: "text", text: `x428: Precondition acceptance required for ${toolName}.` }],
      structuredContent: {
        x428Status: "pending",
        toolName,
        toolArgs: args,
        challengeId: sessionId,
        preconditions: (challenge.preconditions as PreconditionObject[]).map((p) => ({
          type: p.type,
          ...(p.type === "tos" ? { documentUrl: p.documentUrl, tosVersion: p.tosVersion } : {}),
          ...(p.type === "age" ? { minimumAge: p.minimumAge } : {}),
        })),
      },
      _meta: { ui: { resourceUri: UI_RESOURCE_URI } },
    };
  }

  // --- Elicitation fallback path ---
  async function handleElicitationPath(args: any, extra: McpToolExtra, sessionId: string): Promise<any> {
    const challenge = generateChallenge(config.preconditions, resourceUri, { ttlSeconds: 300 });
    const preconditions = challenge.preconditions as PreconditionObject[];
    const elicitReq = buildCombinedElicitation(preconditions);

    let elicitResult: { action: string; content?: Record<string, unknown> };
    try {
      elicitResult = await elicitServer.elicitInput(elicitReq, { requestId: extra.requestId });
    } catch (err) {
      return {
        content: [{ type: "text", text: `x428: Elicitation failed: ${err}` }],
        isError: true,
      };
    }

    if (elicitResult.action !== "accept") {
      return {
        content: [{ type: "text", text: "x428: User declined precondition(s)." }],
        isError: true,
      };
    }

    for (const precondition of preconditions) {
      const fieldKey = `confirm_${precondition.id}`;
      const confirmed = elicitResult.content?.[fieldKey]
        ?? (preconditions.length === 1 && (elicitResult.content?.accept ?? elicitResult.content?.confirm));

      if (!confirmed) {
        return {
          content: [{ type: "text", text: `x428: User did not confirm ${precondition.type} precondition.` }],
          isError: true,
        };
      }
    }

    try {
      const result = await processAttestation(
        challenge, operatorDid, privateKey, resolver, nonceStore, tokenTtl,
      );

      if (result instanceof X428Error) {
        return {
          content: [{ type: "text", text: `x428: Attestation verification failed: ${result.detail}` }],
          isError: true,
        };
      }

      tokenCache.set(`${sessionId}:${resourceUri}`, result);
      return handler(args, extra);
    } catch (err) {
      return {
        content: [{ type: "text", text: `x428: Attestation error: ${err}` }],
        isError: true,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// x428GuardElicitation — backward-compatible wrapper (elicitation only)
// ---------------------------------------------------------------------------

/**
 * Wrap a tool handler with x428 precondition enforcement using elicitation.
 *
 * This is the original x428Guard API — returns a wrapped handler function.
 * Does NOT support MCP Apps auto-detection. Use `x428Guard()` or
 * `x428Protect()` for auto-detection.
 */
export function x428GuardElicitation<TArgs, TResult>(
  config: X428Config & { server: McpServerLike },
  handler: (args: TArgs, extra: McpToolExtra) => Promise<TResult>,
): (args: TArgs, extra: McpToolExtra) => Promise<TResult> {
  const tokenTtl = config.tokenTtl ?? 3600;
  const tokenCache = new Map<string, AttestationToken>();
  const resolver = config.didResolver ?? new DidKeyResolver();
  const nonceStore = config.nonceStore ?? new InMemoryNonceStore();
  const { did: operatorDid, privateKey } = createEphemeralDid();

  return async (args: TArgs, extra: McpToolExtra) => {
    const resUri = config.resourceUri ?? "x428://mcp/tool";
    const sessionId = extra.sessionId ?? "_default";
    const cacheKey = `${sessionId}:${resUri}`;

    const cached = tokenCache.get(cacheKey);
    if (cached && new Date(cached.expiresAt) > new Date()) {
      return handler(args, extra);
    }

    const challenge = generateChallenge(config.preconditions, resUri, { ttlSeconds: 300 });
    const preconditions = challenge.preconditions as PreconditionObject[];
    const elicitReq = buildCombinedElicitation(preconditions);

    let elicitResult: { action: string; content?: Record<string, unknown> };
    try {
      elicitResult = await config.server.elicitInput(elicitReq, { requestId: extra.requestId });
    } catch (err) {
      return { content: [{ type: "text", text: `x428: Elicitation failed: ${err}` }], isError: true } as unknown as TResult;
    }

    if (elicitResult.action !== "accept") {
      return { content: [{ type: "text", text: "x428: User declined precondition(s)." }], isError: true } as unknown as TResult;
    }

    for (const precondition of preconditions) {
      const fieldKey = `confirm_${precondition.id}`;
      const confirmed = elicitResult.content?.[fieldKey]
        ?? (preconditions.length === 1 && (elicitResult.content?.accept ?? elicitResult.content?.confirm));
      if (!confirmed) {
        return { content: [{ type: "text", text: `x428: User did not confirm ${precondition.type} precondition.` }], isError: true } as unknown as TResult;
      }
    }

    try {
      const result = await processAttestation(challenge, operatorDid, privateKey, resolver, nonceStore, tokenTtl);
      if (result instanceof X428Error) {
        return { content: [{ type: "text", text: `x428: Attestation verification failed: ${result.detail}` }], isError: true } as unknown as TResult;
      }
      tokenCache.set(cacheKey, result);
      return handler(args, extra);
    } catch (err) {
      return { content: [{ type: "text", text: `x428: Attestation error: ${err}` }], isError: true } as unknown as TResult;
    }
  };
}
