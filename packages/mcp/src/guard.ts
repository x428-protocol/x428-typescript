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

/** Allow store methods to return sync or async values. */
type MaybePromise<T> = T | Promise<T>;

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

/**
 * Bundled challenge + crypto context.
 * Stored in ChallengeStore for cross-session lookup (e.g., KV-backed).
 */
export interface ChallengeRecord {
  challenge: PreconditionChallenge;
  operatorDid: string;
  privateKey: Uint8Array;
  tokenTtl: number;
  resourceUri: string;
  preconditionConfigs: PreconditionConfig[];
  /** SessionId of the session that generated this challenge.
   *  Used to write accepted preconditions back to the originating session
   *  when x428-attest is called from a different session (e.g., AppBridge). */
  originSessionId: string;
}

/**
 * Persistent challenge store.
 * Stores full ChallengeRecord (challenge + crypto context) so the
 * x428-attest handler can verify from any session (cross-session KV).
 */
export interface ChallengeStore {
  get(challengeId: string): MaybePromise<ChallengeRecord | null>;
  set(challengeId: string, record: ChallengeRecord, ttlMs?: number): MaybePromise<void>;
  delete(challengeId: string): MaybePromise<void>;
}

/** Persistent token store. */
export interface TokenStore {
  get(cacheKey: string): MaybePromise<AttestationToken | null>;
  set(cacheKey: string, token: AttestationToken): MaybePromise<void>;
  /** Remove all tokens for a session (prefix match on `${sessionId}:`). */
  clearSession?(sessionId: string): MaybePromise<void>;
}

/**
 * Tracks accepted preconditions across sessions.
 * With a KV-backed implementation, consent recorded on one session
 * (e.g., AppBridge) is visible from another (e.g., Model).
 */
export interface AcceptedPreconditionStore {
  getAccepted(sessionId: string): MaybePromise<Set<string>>;
  addAll(sessionId: string, keys: string[]): MaybePromise<void>;
  /** Remove all accepted preconditions for a session. */
  clear?(sessionId: string): MaybePromise<void>;
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
  acceptedPreconditionStore?: AcceptedPreconditionStore;
  /** When both Apps and elicitation are supported. Default: "apps". */
  preferredMode?: "apps" | "elicitation";
  /** When neither Apps nor elicitation is supported. Default: "reject". */
  fallbackMode?: "reject" | "apps" | "elicitation";
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
// Default in-memory stores
// ---------------------------------------------------------------------------

const sharedChallenges = new Map<string, ChallengeRecord>();
const sharedTokens = new Map<string, AttestationToken>();
const sharedAccepted = new Map<string, Set<string>>();

const defaultChallengeStore: ChallengeStore = {
  get: (id) => sharedChallenges.get(id) ?? null,
  set: (id, record) => { sharedChallenges.set(id, record); },
  delete: (id) => { sharedChallenges.delete(id); },
};

const defaultTokenStore: TokenStore = {
  get: (key) => sharedTokens.get(key) ?? null,
  set: (key, token) => { sharedTokens.set(key, token); },
};

const defaultAcceptedStore: AcceptedPreconditionStore = {
  getAccepted: (sessionId) => sharedAccepted.get(sessionId) ?? new Set(),
  addAll: (sessionId, keys) => {
    let set = sharedAccepted.get(sessionId);
    if (!set) { set = new Set(); sharedAccepted.set(sessionId, set); }
    for (const k of keys) set.add(k);
  },
};

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

// ---------------------------------------------------------------------------
// Per-server state (registration flags + capability detection)
// ---------------------------------------------------------------------------

interface ServerState {
  attestToolRegistered: boolean;
  revokeToolRegistered: boolean;
  resourceRegistered: boolean;
  /** Raw extensions from client capabilities, captured before Zod strips them. */
  rawExtensions?: Record<string, unknown>;
  extensionsCaptured: boolean;
  /** onAttestation callbacks keyed by challengeId (same-session only, not serializable). */
  attestationCallbacks: Map<string, X428Config["onAttestation"]>;
  /** Shared stores — set on first x428Guard call, used by all tools on this server. */
  challengeStore: ChallengeStore;
  tokenStore: TokenStore;
  acceptedPreconditionStore: AcceptedPreconditionStore;
  storesInitialized: boolean;
}

const serverStateMap = new WeakMap<McpServerWithInit, ServerState>();

function getServerState(server: McpServerWithInit): ServerState {
  let state = serverStateMap.get(server);
  if (!state) {
    state = {
      attestToolRegistered: false,
      revokeToolRegistered: false,
      resourceRegistered: false,
      extensionsCaptured: false,
      attestationCallbacks: new Map(),
      challengeStore: defaultChallengeStore,
      tokenStore: defaultTokenStore,
      acceptedPreconditionStore: defaultAcceptedStore,
      storesInitialized: false,
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
 * Uses the server's shared stores (ChallengeStore, TokenStore, AcceptedPreconditionStore)
 * for cross-session lookup — with KV-backed stores, attestation on one session
 * (AppBridge) is visible from another (Model).
 */
function ensureAttestToolRegistered(server: McpServerWithInit): void {
  const state = getServerState(server);
  if (state.attestToolRegistered) return;
  state.attestToolRegistered = true;

  const resolver = new DidKeyResolver();
  const nonceStore = new InMemoryNonceStore();

  const attestHandler = async (args: { challengeId: string; accepted: boolean }, extra: any) => {
    const { challengeId, accepted } = args;
    const sessionId = extra?.sessionId ?? "_default";

    if (!accepted) {
      return {
        content: [{ type: "text", text: "x428: User declined preconditions." }],
        isError: true,
      };
    }

    // Look up challenge record from shared store
    const record = await state.challengeStore.get(challengeId);
    if (!record) {
      return {
        content: [{ type: "text", text: "x428: Challenge not found or expired." }],
        isError: true,
      };
    }

    const { challenge, operatorDid, privateKey, tokenTtl, resourceUri, preconditionConfigs, originSessionId } = record;

    if (!challenge?.preconditions) {
      return {
        content: [{ type: "text", text: "x428: Invalid challenge record (missing preconditions)." }],
        isError: true,
      };
    }

    try {
      const result = await processAttestation(challenge, operatorDid, privateKey, resolver, nonceStore, tokenTtl);
      if (result instanceof X428Error) {
        return {
          content: [{ type: "text", text: `x428: Attestation verification failed: ${result.detail}` }],
          isError: true,
        };
      }

      // Cache token for the ORIGINATING session (the one that will re-call the tool),
      // not the attesting session (which may be a different DO in Claude Desktop).
      const originCacheKey = `${originSessionId}:${resourceUri}`;
      await state.tokenStore.set(originCacheKey, result);
      // Also cache for the attesting session (same-session attest+re-call case)
      if (sessionId !== originSessionId) {
        const attestCacheKey = `${sessionId}:${resourceUri}`;
        await state.tokenStore.set(attestCacheKey, result);
      }

      // Record accepted preconditions for the originating session
      const acceptedKeys = preconditionConfigs.map((pc) => preconditionKey(pc));
      await state.acceptedPreconditionStore.addAll(originSessionId, acceptedKeys);
      // Also record for the attesting session
      if (sessionId !== originSessionId) {
        await state.acceptedPreconditionStore.addAll(sessionId, acceptedKeys);
      }

      // Fire onAttestation callback if registered for this challenge
      const callback = state.attestationCallbacks.get(challengeId);
      if (callback) {
        callback({
          challengeId,
          sessionId,
          operatorDid,
          attestations: buildAttestationsFromChallenge(challenge),
        });
        state.attestationCallbacks.delete(challengeId);
      }

      // Clean up challenge
      await state.challengeStore.delete(challengeId);

      return {
        content: [{ type: "text", text: "x428: Attestation accepted." }],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `x428: Attestation error: ${err}` }],
        isError: true,
      };
    }
  };

  // Always use tool() for consistent argument parsing.
  // registerTool may handle Zod schemas differently.
  server.tool(
    "x428-attest",
    "x428 attestation endpoint",
    { challengeId: z.string(), accepted: z.boolean() },
    attestHandler,
  );
}

/**
 * Register the x428-revoke tool (once per server).
 * Clears accepted preconditions and cached tokens for the calling session.
 * Does NOT affect the audit log.
 */
function ensureRevokeToolRegistered(server: McpServerWithInit): void {
  const state = getServerState(server);
  if (state.revokeToolRegistered) return;
  state.revokeToolRegistered = true;

  const revokeHandler = async (_args: Record<string, never>, extra: any) => {
    const sessionId = extra?.sessionId ?? "_default";

    const cleared: string[] = [];

    if (state.acceptedPreconditionStore.clear) {
      await state.acceptedPreconditionStore.clear(sessionId);
      cleared.push("accepted preconditions");
    }

    if (state.tokenStore.clearSession) {
      await state.tokenStore.clearSession(sessionId);
      cleared.push("cached tokens");
    }

    if (cleared.length === 0) {
      return {
        content: [{ type: "text", text: "x428: Revoke not supported by this server's stores." }],
        isError: true,
      };
    }

    return {
      content: [{ type: "text", text: `x428: Revoked ${cleared.join(" and ")} for this session.` }],
    };
  };

  server.tool(
    "x428-revoke",
    "Revoke accepted x428 preconditions for this session",
    {},
    revokeHandler,
  );
}

// ---------------------------------------------------------------------------
// Mode detection
// ---------------------------------------------------------------------------

export type GuardMode = "apps" | "elicitation" | "reject";

function detectMode(
  mcpServer: McpServerWithInit,
  state: ServerState,
  config: X428Config,
): GuardMode {
  const caps = mcpServer.server.getClientCapabilities?.() ?? {};
  const hasElicitation = !!(caps as any).elicitation;
  const hasApps = !!state.rawExtensions;

  if (hasApps && hasElicitation) {
    return config.preferredMode ?? "apps";
  }
  if (hasApps) return "apps";
  if (hasElicitation) return "elicitation";
  return config.fallbackMode ?? "reject";
}

// ---------------------------------------------------------------------------
// x428Guard — MCP Apps guard
// ---------------------------------------------------------------------------

/**
 * Register a single MCP tool with x428 precondition enforcement.
 *
 * Auto-detects client capabilities at call time and selects the appropriate
 * interaction mode:
 * - **Apps**: Returns `structuredContent` with `_meta.ui.resourceUri` for
 *   inline iframe rendering. The App calls `x428-attest` to confirm.
 * - **Elicitation**: Uses `server.elicitInput()` to present confirmation
 *   dialogs inline within the same tool call.
 * - **Reject**: Returns an error indicating the client lacks support.
 *
 * When both Apps and elicitation are available, `config.preferredMode`
 * controls which is used (default: `"apps"`). When neither is available,
 * `config.fallbackMode` determines behavior (default: `"reject"`).
 *
 * All tools on a server share the same stores (ChallengeStore, TokenStore,
 * AcceptedPreconditionStore). Stores are set from the first x428Guard call's
 * config; subsequent calls use the same stores.
 */
export function x428Guard(
  mcpServer: McpServerWithInit,
  config: X428Config,
  toolName: string,
  toolConfig: { description?: string; inputSchema?: Record<string, unknown> },
  handler: (args: any, extra: McpToolExtra) => Promise<any>,
): void {
  const tokenTtl = config.tokenTtl ?? 3600;
  const resourceUri = config.resourceUri ?? `x428://mcp/tool/${toolName}`;
  const { did: operatorDid, privateKey } = createEphemeralDid();
  const state = getServerState(mcpServer);

  // Initialize shared stores from first config (subsequent calls reuse)
  if (!state.storesInitialized) {
    state.storesInitialized = true;
    if (config.challengeStore) state.challengeStore = config.challengeStore;
    if (config.tokenStore) state.tokenStore = config.tokenStore;
    if (config.acceptedPreconditionStore) state.acceptedPreconditionStore = config.acceptedPreconditionStore;
  }

  // Capture raw extensions before Zod strips them (for future use)
  ensureExtensionsCapture(mcpServer, state);

  // Eagerly register shared infrastructure
  ensureResourceRegistered(mcpServer);
  ensureAttestToolRegistered(mcpServer);
  ensureRevokeToolRegistered(mcpServer);

  const handleApps = async (
    args: any,
    extra: McpToolExtra,
    remainingPreconditions: PreconditionConfig[],
  ) => {
    const sessionId = extra.sessionId ?? "_default";
    const challengeId = crypto.randomUUID();
    const challenge = generateChallenge(remainingPreconditions, resourceUri, { ttlSeconds: 300 });
    const preconditions = challenge.preconditions as PreconditionObject[];

    // Store full challenge record (challenge + crypto context) in shared store.
    // With KV-backed store, the x428-attest handler on any session can find it.
    await state.challengeStore.set(challengeId, {
      challenge,
      operatorDid,
      privateKey,
      tokenTtl,
      resourceUri,
      preconditionConfigs: config.preconditions,
      originSessionId: sessionId,
    });

    // Store onAttestation callback in server state (same-session only, not serializable)
    if (config.onAttestation) {
      state.attestationCallbacks.set(challengeId, config.onAttestation);
    }

    return {
      content: [{ type: "text", text: `x428: Precondition acceptance required for ${toolName}.` }],
      structuredContent: {
        x428Status: "pending",
        toolName,
        toolArgs: args,
        challengeId,
        preconditions: preconditions.map((p) => ({
          type: p.type,
          ...(p.type === "tos" ? { documentUrl: p.documentUrl, tosVersion: p.tosVersion } : {}),
          ...(p.type === "age" ? { minimumAge: p.minimumAge } : {}),
        })),
      },
      _meta: UI_META,
    };
  };

  const handleElicitation = async (
    args: any,
    extra: McpToolExtra,
    remainingPreconditions: PreconditionConfig[],
  ) => {
    // Unlike handleApps, the elicitation path does not store or delete from
    // the challenge store. Elicitation is synchronous within this call:
    // challenge generation, user confirmation via elicitInput(), and
    // attestation verification all complete before returning, so there is
    // no need for cross-session challenge lookup.
    const sessionId = extra.sessionId ?? "_default";
    const elicitFn = mcpServer.server.elicitInput;
    if (!elicitFn) {
      return {
        content: [{ type: "text", text: "x428: Server does not support elicitation." }],
        isError: true,
      };
    }

    const resolver = config.didResolver ?? new DidKeyResolver();
    const nonceStore = config.nonceStore ?? new InMemoryNonceStore();
    const challengeId = crypto.randomUUID();
    const challenge = generateChallenge(remainingPreconditions, resourceUri, { ttlSeconds: 300 });
    const preconditions = challenge.preconditions as PreconditionObject[];
    const elicitReq = buildCombinedElicitation(preconditions);

    let elicitResult: { action: string; content?: Record<string, unknown> };
    try {
      elicitResult = await elicitFn.call(mcpServer.server, elicitReq, { requestId: extra.requestId });
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

    // Validate all precondition fields were confirmed
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
      const result = await processAttestation(challenge, operatorDid, privateKey, resolver, nonceStore, tokenTtl);
      if (result instanceof X428Error) {
        return {
          content: [{ type: "text", text: `x428: Attestation verification failed: ${result.detail}` }],
          isError: true,
        };
      }

      // Cache token by sessionId + resourceUri
      const cacheKey = `${sessionId}:${resourceUri}`;
      await state.tokenStore.set(cacheKey, result);

      // Record accepted preconditions in shared store
      const acceptedKeys = config.preconditions.map((pc) => preconditionKey(pc));
      await state.acceptedPreconditionStore.addAll(sessionId, acceptedKeys);

      // Fire onAttestation callback
      if (config.onAttestation) {
        config.onAttestation({
          challengeId,
          sessionId,
          operatorDid,
          attestations: buildAttestationsFromChallenge(challenge),
        });
      }

      return handler(args, extra);
    } catch (err) {
      return {
        content: [{ type: "text", text: `x428: Attestation error: ${err}` }],
        isError: true,
      };
    }
  };

  const toolCallback = async (args: any, extra: McpToolExtra) => {
    const sessionId = extra.sessionId ?? "_default";
    const cacheKey = `${sessionId}:${resourceUri}`;

    // Check token cache — works for re-calls from the App iframe
    const cached = await state.tokenStore.get(cacheKey);
    if (cached && new Date(cached.expiresAt) > new Date()) {
      return handler(args, extra);
    }

    // Filter to only unattested preconditions (consent is per-precondition,
    // not per-tool — accepting TOS for search also satisfies TOS for info).
    const accepted = await state.acceptedPreconditionStore.getAccepted(sessionId);
    const remainingPreconditions = accepted.size > 0
      ? config.preconditions.filter((pc) => !accepted.has(preconditionKey(pc)))
      : config.preconditions;

    // All preconditions already accepted → run handler directly
    if (remainingPreconditions.length === 0) {
      return handler(args, extra);
    }

    // Detect mode based on client capabilities
    const mode = detectMode(mcpServer, state, config);

    if (mode === "reject") {
      return {
        content: [{ type: "text", text: "x428: Precondition acceptance required but client does not support Apps or elicitation." }],
        isError: true,
      };
    }

    if (mode === "elicitation") {
      return handleElicitation(args, extra, remainingPreconditions);
    }

    return handleApps(args, extra, remainingPreconditions);
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
