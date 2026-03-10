import type {
  AttestationToken,
  AttestationObject,
  PreconditionObject,
  PreconditionChallenge,
  PreconditionConfig,
  DidResolver,
  NonceStore,
} from "@x428/core";
import {
  generateChallenge,
  buildAttestation,
  verifyAttestation,
  X428Error,
  DidKeyResolver,
  InMemoryNonceStore,
} from "@x428/core";
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

/** Persistent challenge store (replaces module-level Map). */
export interface ChallengeStore {
  get(challengeId: string): PreconditionChallenge | null;
  set(challengeId: string, challenge: PreconditionChallenge, ttlMs?: number): void;
  delete(challengeId: string): void;
}

/** Persistent token store (replaces module-level Map). */
export interface TokenStore {
  get(cacheKey: string): AttestationToken | null;
  set(cacheKey: string, token: AttestationToken): void;
}

export interface X428Config {
  preconditions: PreconditionConfig[];
  /** Required for elicitation fallback. Typically `mcpServer.server`. */
  server?: McpServerLike;
  resourceUri?: string;
  tokenTtl?: number;
  didResolver?: DidResolver;
  nonceStore?: NonceStore;
  challengeStore?: ChallengeStore;
  tokenStore?: TokenStore;
  /** Called after successful attestation verification. */
  onAttestation?: (entry: {
    challengeId: string;
    sessionId: string;
    operatorDid: string;
    attestations: unknown[];
  }) => void;
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

// ---------------------------------------------------------------------------
// Shared pending context — module-level so it works across MCP sessions.
// Claude Desktop creates separate AppBridge and Model sessions with different
// Mcp-Session-Id values (ext-apps#481). The App iframe's tools/call goes
// through the AppBridge session, not the Model session that originally called
// the tool. Keying by challengeId (UUID) instead of sessionId lets the
// x428-attest call find the context regardless of which session it arrives on.
// ---------------------------------------------------------------------------

/** Pending challenges, keyed by challengeId (UUID) for cross-session lookup. */
const sharedChallenges = new Map<string, PreconditionChallenge>();

/** Attestation tokens, keyed by "sessionId:resourceUri" for standard lookup. */
const sharedTokens = new Map<string, AttestationToken>();

const defaultChallengeStore: ChallengeStore = {
  get: (id) => sharedChallenges.get(id) ?? null,
  set: (id, challenge) => { sharedChallenges.set(id, challenge); },
  delete: (id) => { sharedChallenges.delete(id); },
};

const defaultTokenStore: TokenStore = {
  get: (key) => sharedTokens.get(key) ?? null,
  set: (key, token) => { sharedTokens.set(key, token); },
};

/** Per-challenge crypto context so the shared attest handler can verify any tool's challenge. */
interface ChallengeContext {
  operatorDid: string;
  privateKey: Uint8Array;
  resolver: DidResolver;
  nonceStore: NonceStore;
  tokenTtl: number;
  resourceUri: string;
  challengeStore: ChallengeStore;
  tokenStore: TokenStore;
  onAttestation?: X428Config["onAttestation"];
  /** Original precondition configs, used to mark them as accepted. */
  preconditionConfigs: PreconditionConfig[];
}

/**
 * Serializable challenge data for cross-session lookup (Claude Desktop).
 * Contains only plain data — no DO-specific store references that would
 * cause "Cannot perform I/O on behalf of a different Durable Object".
 */
interface CrossSessionChallengeData {
  challenge: PreconditionChallenge;
  operatorDid: string;
  privateKey: Uint8Array;
  tokenTtl: number;
  resourceUri: string;
  preconditionConfigs: PreconditionConfig[];
}

/**
 * Module-level map for cross-session challenge lookup.
 * Claude Desktop creates separate AppBridge and Model sessions (ext-apps#481),
 * each mapping to a different Durable Object. The Model DO creates the challenge;
 * the AppBridge DO calls x428-attest. This map lets the AppBridge find the
 * challenge data without accessing the Model DO's storage.
 *
 * Only stores serializable data — no DO-specific I/O objects.
 */
const crossSessionChallenges = new Map<string, CrossSessionChallengeData>();

/**
 * Compute a stable identity key for a precondition config.
 * Two preconditions with the same key represent the same consent
 * (e.g., same TOS document+version, same age threshold).
 */
function preconditionKey(p: PreconditionConfig): string {
  switch (p.type) {
    case "tos":
      return `tos:${p.documentUrl}:${p.tosVersion}`;
    case "age":
      return `age:${p.minimumAge}`;
    case "identity":
      return "identity";
  }
}

// Per-server state (registration flags + capability detection)
interface ServerState {
  attestToolRegistered: boolean;
  resourceRegistered: boolean;
  /** Raw extensions from client capabilities, captured before Zod strips them. */
  rawExtensions?: Record<string, unknown>;
  extensionsCaptured: boolean;
  /** Per-challenge crypto context, scoped to this server instance (not module-level). */
  challengeContexts: Map<string, ChallengeContext>;
  /** Accepted precondition keys per session, for cross-tool consent sharing. */
  acceptedPreconditions: Map<string, Set<string>>;
}

const serverStateMap = new WeakMap<McpServerWithInit, ServerState>();

function getServerState(server: McpServerWithInit): ServerState {
  let state = serverStateMap.get(server);
  if (!state) {
    state = {
      attestToolRegistered: false,
      resourceRegistered: false,
      extensionsCaptured: false,
      challengeContexts: new Map(),
      acceptedPreconditions: new Map(),
    };
    serverStateMap.set(server, state);
  }
  return state;
}

/**
 * Intercept the low-level Server's _onrequest to capture `extensions`
 * from the initialize request before Zod strips it.
 *
 * The MCP SDK's ClientCapabilitiesSchema uses z.object() without
 * .passthrough(), so `extensions` is silently dropped during Zod parsing
 * in setRequestHandler(). The raw request at _onrequest() still has it.
 *
 * Uses Object.defineProperty to intercept both immediate and deferred
 * assignment of _onrequest (e.g., when server.connect() runs after init()).
 */
function ensureExtensionsCapture(mcpServer: McpServerWithInit, state: ServerState): void {
  if (state.extensionsCaptured) return;
  state.extensionsCaptured = true;

  const rawServer = mcpServer.server as any;

  function wrapOnRequest(fn: Function): Function {
    return function (this: any, request: any, extra: any) {
      if (request?.method === "initialize" && request?.params?.capabilities?.extensions) {
        state.rawExtensions = request.params.capabilities.extensions;
      }
      return fn.call(this, request, extra);
    };
  }

  // If _onrequest is already set (normal McpServer usage), wrap it now
  let currentOnRequest = rawServer._onrequest;
  if (currentOnRequest) {
    rawServer._onrequest = wrapOnRequest(currentOnRequest);
    return;
  }

  // If _onrequest is NOT set yet (McpAgent: init() before connect()),
  // intercept the future assignment via defineProperty
  Object.defineProperty(rawServer, "_onrequest", {
    get() {
      return currentOnRequest;
    },
    set(fn: Function) {
      currentOnRequest = wrapOnRequest(fn);
    },
    configurable: true,
    enumerable: true,
  });
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
 * Register the x428-attest tool (once per server).
 * This tool is called by the MCP App UI to confirm precondition acceptance.
 * Uses server-scoped challengeContexts to find the correct crypto context for each challenge.
 */
function ensureAttestToolRegistered(
  server: McpServerWithInit,
): void {
  const state = getServerState(server);
  if (state.attestToolRegistered) return;
  state.attestToolRegistered = true;

  // Capture state ref so the handler uses the correct per-server context map
  const { challengeContexts } = state;

  const attestHandler = async (args: { challengeId: string; accepted: boolean; challengeData?: string }, extra: McpToolExtra) => {
    if (!args.accepted) {
      return {
        content: [{ type: "text", text: "x428: User declined preconditions." }],
        isError: true,
      };
    }

    // Look up challenge context: try per-server state first (same session),
    // then fall back to module-level cross-session map (Claude Desktop),
    // then fall back to challengeData sent by the App UI (cross-isolate).
    const ctx = challengeContexts.get(args.challengeId);
    const crossCtx = !ctx ? crossSessionChallenges.get(args.challengeId) : null;

    // Parse challengeData from App UI if no local context found
    let inlineChallenge: PreconditionChallenge | null = null;
    let inlinePreconditionConfigs: PreconditionConfig[] | null = null;
    if (!ctx && !crossCtx && args.challengeData) {
      try {
        const parsed = JSON.parse(args.challengeData);
        inlineChallenge = parsed.challenge;
        inlinePreconditionConfigs = parsed.preconditionConfigs;
      } catch {
        // Invalid JSON — fall through to error
      }
    }

    if (!ctx && !crossCtx && !inlineChallenge) {
      return {
        content: [{ type: "text", text: "x428: No pending challenge found." }],
        isError: true,
      };
    }

    // Use per-server context if available, then cross-session, then inline
    const challenge = ctx
      ? ctx.challengeStore.get(args.challengeId)
      : crossCtx?.challenge ?? inlineChallenge;
    const preconditionConfigs = ctx?.preconditionConfigs ?? crossCtx?.preconditionConfigs ?? inlinePreconditionConfigs ?? [];
    const tokenTtl = ctx?.tokenTtl ?? crossCtx?.tokenTtl ?? 3600;
    const resourceUri = ctx?.resourceUri ?? crossCtx?.resourceUri ?? "x428://mcp/tool";
    // Use original keypair if available, otherwise create fresh (self-attestation)
    const ephemeral = !ctx && !crossCtx ? createEphemeralDid() : null;
    const operatorDid = ctx?.operatorDid ?? crossCtx?.operatorDid ?? ephemeral!.did;
    const privateKey = ctx?.privateKey ?? crossCtx?.privateKey ?? ephemeral!.privateKey;
    // For cross-session/inline, use fresh resolver/nonceStore (stateless for self-attestation)
    const resolver = ctx?.resolver ?? new DidKeyResolver();
    const nonceStore = ctx?.nonceStore ?? new InMemoryNonceStore();

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

      // Fire audit callback (only available in same-session context)
      const sessionId = extra.sessionId ?? "_default";
      if (ctx?.onAttestation) {
        ctx.onAttestation({
          challengeId: args.challengeId,
          sessionId,
          operatorDid,
          attestations: buildAttestationsFromChallenge(challenge),
        });
      }

      // Cache token (only if we have the original stores — same session)
      if (ctx) {
        const cacheKey = `${sessionId}:${resourceUri}`;
        ctx.tokenStore.set(cacheKey, result);
        ctx.challengeStore.delete(args.challengeId);
      }
      challengeContexts.delete(args.challengeId);
      crossSessionChallenges.delete(args.challengeId);

      // Record accepted preconditions so other tools with the same
      // preconditions don't re-prompt (consent is per-precondition, not per-tool).
      let accepted = state.acceptedPreconditions.get(sessionId);
      if (!accepted) {
        accepted = new Set();
        state.acceptedPreconditions.set(sessionId, accepted);
      }
      for (const pc of preconditionConfigs) {
        accepted.add(preconditionKey(pc));
      }

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
      "x428-attest",
      {
        description: "x428 attestation endpoint",
        inputSchema: { challengeId: z.string(), accepted: z.boolean(), challengeData: z.string().optional() },
        _meta: { ui: { resourceUri: UI_RESOURCE_URI, visibility: ["app"] }, "ui/resourceUri": UI_RESOURCE_URI },
      },
      attestHandler,
    );
  } else {
    server.tool(
      "x428-attest",
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
 * Returns `structuredContent` with precondition data and `_meta.ui.resourceUri`.
 * Apps-capable hosts (Claude Desktop, Inspector Apps tab) render an inline
 * iframe for acceptance; the App calls `x428-attest` then re-calls the tool.
 *
 * For clients that support elicitation but not Apps (e.g. Inspector Tools tab),
 * use `x428GuardElicitation` instead.
 */
export function x428Guard(
  mcpServer: McpServerWithInit,
  config: X428Config,
  toolName: string,
  toolConfig: { description?: string; inputSchema?: Record<string, unknown> },
  handler: (args: any, extra: McpToolExtra) => Promise<any>,
): void {
  const tokenTtl = config.tokenTtl ?? 3600;
  const resolver = config.didResolver ?? new DidKeyResolver();
  const nonceStore = config.nonceStore ?? new InMemoryNonceStore();
  const resourceUri = config.resourceUri ?? `x428://mcp/tool/${toolName}`;
  const { did: operatorDid, privateKey } = createEphemeralDid();
  const state = getServerState(mcpServer);
  const cStore = config.challengeStore ?? defaultChallengeStore;
  const tStore = config.tokenStore ?? defaultTokenStore;

  // Capture raw extensions before Zod strips them (for future use)
  ensureExtensionsCapture(mcpServer, state);

  // Eagerly register shared infrastructure
  ensureResourceRegistered(mcpServer);
  ensureAttestToolRegistered(mcpServer);

  const toolCallback = async (args: any, extra: McpToolExtra) => {
    // Check token cache by sessionId — works for re-calls from the App
    // iframe since x428-attest and the re-call use the same session.
    const sessionId = extra.sessionId ?? "_default";
    const cacheKey = `${sessionId}:${resourceUri}`;
    const cached = tStore.get(cacheKey);
    if (cached && new Date(cached.expiresAt) > new Date()) {
      return handler(args, extra);
    }

    // Filter to only unattested preconditions (consent is per-precondition,
    // not per-tool — accepting TOS for search also satisfies TOS for info).
    const accepted = state.acceptedPreconditions.get(sessionId);
    const remainingPreconditions = accepted
      ? config.preconditions.filter((pc) => !accepted.has(preconditionKey(pc)))
      : config.preconditions;

    // All preconditions already accepted → run handler directly
    if (remainingPreconditions.length === 0) {
      return handler(args, extra);
    }

    const challengeId = crypto.randomUUID();
    const challenge = generateChallenge(remainingPreconditions, resourceUri, { ttlSeconds: 300 });
    const preconditions = challenge.preconditions as PreconditionObject[];

    // Store challenge keyed by challengeId (UUID).
    // x428-attest finds it by challengeId regardless of session.
    cStore.set(challengeId, challenge);

    // Store per-challenge crypto context so the shared attest handler
    // can verify this specific tool's challenge with the right keypair.
    state.challengeContexts.set(challengeId, {
      operatorDid, privateKey, resolver, nonceStore, tokenTtl,
      resourceUri, challengeStore: cStore, tokenStore: tStore,
      onAttestation: config.onAttestation,
      preconditionConfigs: config.preconditions,
    });

    // Also store in module-level map for cross-session lookup (Claude Desktop).
    // Only serializable data — no DO-specific store references.
    crossSessionChallenges.set(challengeId, {
      challenge, operatorDid, privateKey, tokenTtl,
      resourceUri, preconditionConfigs: config.preconditions,
    });

    // Bundle challenge + preconditionConfigs for cross-session round-trip.
    // The App UI sends this back with x428-attest so the attest handler
    // can verify without needing shared storage across DO isolates.
    const challengeData = JSON.stringify({
      challenge,
      preconditionConfigs: remainingPreconditions,
    });

    return {
      content: [{ type: "text", text: `x428: Precondition acceptance required for ${toolName}.` }],
      structuredContent: {
        x428Status: "pending",
        toolName,
        toolArgs: args,
        challengeId,
        challengeData,
        preconditions: preconditions.map((p) => ({
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
