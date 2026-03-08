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
import { z } from "zod";

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
  /** registerTool supports _meta in tool definitions (required for MCP Apps). */
  registerTool?(name: string, config: Record<string, unknown>, cb: Function): any;
  /** registerResource supports mimeType config. */
  registerResource?(name: string, uri: string, config: Record<string, unknown>, cb: Function): any;
  resource?(...args: any[]): any;
}

// UI resource URI shared by all guarded tools
const UI_RESOURCE_URI = "ui://x428/guard";
const RESOURCE_MIME_TYPE = "text/html;profile=mcp-app";
// ext-apps SDK uses both nested and flat key formats for _meta
const UI_META = { ui: { resourceUri: UI_RESOURCE_URI }, "ui/resourceUri": UI_RESOURCE_URI };

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

// Per-server shared state
interface ServerState {
  pendingChallenges: Map<string, PreconditionChallenge>;
  attestToolRegistered: boolean;
  resourceRegistered: boolean;
}

const serverStateMap = new WeakMap<McpServerWithInit, ServerState>();

function getServerState(server: McpServerWithInit): ServerState {
  let state = serverStateMap.get(server);
  if (!state) {
    state = {
      pendingChallenges: new Map(),
      attestToolRegistered: false,
      resourceRegistered: false,
    };
    serverStateMap.set(server, state);
  }
  return state;
}

/**
 * Register the shared UI resource (once per server).
 * Uses registerResource if available, falls back to resource().
 */
function ensureResourceRegistered(server: McpServerWithInit): void {
  const state = getServerState(server);
  if (state.resourceRegistered) return;
  state.resourceRegistered = true;

  if (server.registerResource) {
    server.registerResource(
      "x428-guard-ui",
      UI_RESOURCE_URI,
      { mimeType: RESOURCE_MIME_TYPE },
      async () => ({
        contents: [{ uri: UI_RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: buildAppHtml() }],
      }),
    );
  } else if (server.resource) {
    server.resource(
      "x428-guard-ui",
      UI_RESOURCE_URI,
      { mimeType: RESOURCE_MIME_TYPE },
      async () => ({
        contents: [{ uri: UI_RESOURCE_URI, mimeType: RESOURCE_MIME_TYPE, text: buildAppHtml() }],
      }),
    );
  }
}

/**
 * Register the x428/attest tool (once per server).
 * This tool is called by the MCP App UI to confirm precondition acceptance.
 */
function ensureAttestToolRegistered(
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
  const state = getServerState(server);
  if (state.attestToolRegistered) return;
  state.attestToolRegistered = true;

  const attestHandler = async (args: { challengeId: string; accepted: boolean }, extra: McpToolExtra) => {
    const sessionId = extra.sessionId ?? "_default";

    if (!args.accepted) {
      return {
        content: [{ type: "text", text: "x428: User declined preconditions." }],
        isError: true,
      };
    }

    const challenge = pendingChallenges.get(args.challengeId ?? sessionId);
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
      pendingChallenges.delete(args.challengeId ?? sessionId);

      return {
        content: [{ type: "text", text: "x428: Attestation accepted. You may now use the tool." }],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `x428: Attestation error: ${err}` }],
        isError: true,
      };
    }
  };

  // Register with visibility: ["app"] if registerTool available (hides from model)
  if (server.registerTool) {
    server.registerTool(
      "x428/attest",
      {
        description: "x428 attestation endpoint",
        inputSchema: { challengeId: z.string(), accepted: z.boolean() },
        _meta: { ui: { resourceUri: UI_RESOURCE_URI, visibility: ["app"] }, "ui/resourceUri": UI_RESOURCE_URI },
      },
      attestHandler,
    );
  } else {
    server.tool(
      "x428/attest",
      "x428 attestation endpoint",
      { challengeId: z.string(), accepted: z.boolean() },
      attestHandler,
    );
  }
}

// ---------------------------------------------------------------------------
// x428Guard — MCP Apps guard
// ---------------------------------------------------------------------------

/**
 * Register a single MCP tool with x428 precondition enforcement via MCP Apps.
 *
 * Tools are registered with `_meta.ui.resourceUri` so MCP Apps-capable hosts
 * (Inspector, Claude Desktop) render an inline acceptance UI. The tool returns
 * `structuredContent` with precondition data for the App, plus text `content`
 * as fallback for the model context.
 *
 * The host decides whether to render the App UI — no runtime capability
 * detection is needed.
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
  const state = getServerState(mcpServer);

  // Eagerly register shared infrastructure
  ensureResourceRegistered(mcpServer);
  ensureAttestToolRegistered(
    mcpServer, state.pendingChallenges,
    operatorDid, privateKey, resolver, nonceStore, tokenTtl, tokenCache, resourceUri,
  );

  function getCachedToken(sessionId: string): AttestationToken | undefined {
    const key = `${sessionId}:${resourceUri}`;
    const cached = tokenCache.get(key);
    if (cached && new Date(cached.expiresAt) > new Date()) return cached;
    return undefined;
  }

  const toolCallback = async (args: any, extra: McpToolExtra) => {
    const sessionId = extra.sessionId ?? "_default";
    const cached = getCachedToken(sessionId);
    if (cached) return handler(args, extra);

    // Generate challenge and return structuredContent for the App UI.
    // The host renders the App iframe; the App calls x428/attest on acceptance.
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
      _meta: UI_META,
    };
  };

  // Use registerTool for _meta.ui support, fall back to tool() for compat
  if (mcpServer.registerTool) {
    mcpServer.registerTool(toolName, {
      ...(toolConfig.description ? { description: toolConfig.description } : {}),
      ...(toolConfig.inputSchema ? { inputSchema: toolConfig.inputSchema } : {}),
      _meta: UI_META,
    }, toolCallback);
  } else {
    const toolArgs: any[] = [toolName];
    if (toolConfig.description) toolArgs.push(toolConfig.description);
    if (toolConfig.inputSchema) toolArgs.push(toolConfig.inputSchema);
    toolArgs.push(toolCallback);
    mcpServer.tool(...toolArgs);
  }
}

// ---------------------------------------------------------------------------
// x428GuardElicitation — elicitation-only guard (non-Apps clients)
// ---------------------------------------------------------------------------

/**
 * Wrap a tool handler with x428 precondition enforcement using elicitation.
 *
 * This is for MCP clients that don't support MCP Apps. Returns a wrapped
 * handler function that uses `elicitInput()` for confirmation dialogs.
 * Use `x428Guard()` for MCP Apps-capable clients.
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
