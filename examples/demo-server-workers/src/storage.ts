/**
 * Storage implementations for the Workers x428 demo server.
 *
 * Dual-write stores: in-memory (instant, same-DO) + KV (cross-session).
 * Reads check in-memory first, fall back to KV. This avoids KV eventual
 * consistency issues for same-session flows while enabling cross-session
 * state sharing for Claude Desktop's multi-DO architecture.
 *
 * SQLite audit log uses the DO's built-in SQLite (per-DO, append-only).
 */

import type { AttestationToken, PreconditionChallenge, PreconditionConfig } from "@x428/core";
import type { ChallengeRecord, ChallengeStore, TokenStore, AcceptedPreconditionStore } from "@x428/mcp";

/** KV namespace interface matching Cloudflare Workers KV. */
export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Dual-write challenge store (in-memory + KV)
// ---------------------------------------------------------------------------

/** Serializable form of ChallengeRecord for KV storage. */
interface SerializedChallengeRecord {
  challenge: PreconditionChallenge;
  operatorDid: string;
  privateKeyBase64: string;
  tokenTtl: number;
  resourceUri: string;
  preconditionConfigs: PreconditionConfig[];
}

export class DualChallengeStore implements ChallengeStore {
  private memory = new Map<string, ChallengeRecord>();

  constructor(private kv: KVNamespace, private prefix = "x428:challenge:") {}

  async get(challengeId: string): Promise<ChallengeRecord | null> {
    // In-memory first (same-DO, instant)
    const local = this.memory.get(challengeId);
    if (local) return local;

    // Fall back to KV (cross-session)
    const raw = await this.kv.get(this.prefix + challengeId);
    if (!raw) return null;
    const data: SerializedChallengeRecord = JSON.parse(raw);
    return {
      challenge: data.challenge,
      operatorDid: data.operatorDid,
      privateKey: base64ToUint8Array(data.privateKeyBase64),
      tokenTtl: data.tokenTtl,
      resourceUri: data.resourceUri,
      preconditionConfigs: data.preconditionConfigs,
    };
  }

  async set(challengeId: string, record: ChallengeRecord, ttlMs?: number): Promise<void> {
    // Write to both stores
    this.memory.set(challengeId, record);

    const data: SerializedChallengeRecord = {
      challenge: record.challenge,
      operatorDid: record.operatorDid,
      privateKeyBase64: uint8ArrayToBase64(record.privateKey),
      tokenTtl: record.tokenTtl,
      resourceUri: record.resourceUri,
      preconditionConfigs: record.preconditionConfigs,
    };
    const ttlSeconds = ttlMs ? Math.ceil(ttlMs / 1000) : 300;
    await this.kv.put(this.prefix + challengeId, JSON.stringify(data), {
      expirationTtl: ttlSeconds,
    });
  }

  async delete(challengeId: string): Promise<void> {
    this.memory.delete(challengeId);
    await this.kv.delete(this.prefix + challengeId);
  }
}

// ---------------------------------------------------------------------------
// Dual-write token store (in-memory + KV)
// ---------------------------------------------------------------------------

export class DualTokenStore implements TokenStore {
  private memory = new Map<string, AttestationToken>();

  constructor(private kv: KVNamespace, private prefix = "x428:token:") {}

  async get(cacheKey: string): Promise<AttestationToken | null> {
    const local = this.memory.get(cacheKey);
    if (local) return local;

    const raw = await this.kv.get(this.prefix + cacheKey);
    if (!raw) return null;
    return JSON.parse(raw);
  }

  async set(cacheKey: string, token: AttestationToken): Promise<void> {
    this.memory.set(cacheKey, token);

    const expiresAt = new Date(token.expiresAt).getTime();
    const ttlSeconds = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000));
    await this.kv.put(this.prefix + cacheKey, JSON.stringify(token), {
      expirationTtl: ttlSeconds,
    });
  }
}

// ---------------------------------------------------------------------------
// Dual-write accepted precondition store (in-memory + KV)
// ---------------------------------------------------------------------------

/**
 * Dual-write accepted precondition store.
 *
 * Scoped by sessionId — each MCP session must accept preconditions
 * independently. This is correct for a public multi-user demo server
 * where different sessions represent different users/agents.
 *
 * For Claude Desktop's multi-DO architecture (AppBridge + Model in
 * separate DOs), both sessions get their own acceptance flow.
 */
export class DualAcceptedPreconditionStore implements AcceptedPreconditionStore {
  private memory = new Map<string, Set<string>>();

  constructor(private kv: KVNamespace, private prefix = "x428:accepted:", private ttlSeconds = 86400) {}

  async getAccepted(sessionId: string): Promise<Set<string>> {
    // In-memory first (same-DO, instant)
    const local = this.memory.get(sessionId);
    if (local && local.size > 0) return new Set(local);

    // Fall back to KV (cross-request persistence for same session)
    const raw = await this.kv.get(this.prefix + sessionId);
    if (!raw) return new Set();
    return new Set(JSON.parse(raw));
  }

  async addAll(sessionId: string, keys: string[]): Promise<void> {
    let set = this.memory.get(sessionId);
    if (!set) { set = new Set(); this.memory.set(sessionId, set); }
    for (const k of keys) set.add(k);

    // Merge with KV for same-session persistence across requests
    const raw = await this.kv.get(this.prefix + sessionId);
    const existing: string[] = raw ? JSON.parse(raw) : [];
    const merged = new Set(existing);
    for (const k of keys) merged.add(k);
    await this.kv.put(this.prefix + sessionId, JSON.stringify([...merged]), {
      expirationTtl: this.ttlSeconds,
    });
  }
}

// ---------------------------------------------------------------------------
// SQLite audit log (per-DO, append-only)
// ---------------------------------------------------------------------------

/** SQL executor interface matching DO's ctx.storage.sql */
export interface SqlStorage {
  exec(query: string, ...bindings: unknown[]): { toArray(): Record<string, unknown>[]; one(): Record<string, unknown> };
}

export function initAuditTable(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS attestation_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      challenge_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      operator_did TEXT NOT NULL,
      attestations_json TEXT NOT NULL,
      signature TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);
}

export interface AuditEntry {
  challengeId: string;
  sessionId: string;
  operatorDid: string;
  attestations: unknown[];
  signature: string;
}

export class SqliteAuditLog {
  constructor(private sql: SqlStorage) {}

  append(entry: AuditEntry): void {
    this.sql.exec(
      "INSERT INTO attestation_log (challenge_id, session_id, operator_did, attestations_json, signature, created_at) VALUES (?, ?, ?, ?, ?, ?);",
      entry.challengeId,
      entry.sessionId,
      entry.operatorDid,
      JSON.stringify(entry.attestations),
      entry.signature,
      Date.now(),
    );
  }
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------

function uint8ArrayToBase64(arr: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

function base64ToUint8Array(b64: string): Uint8Array {
  const binary = atob(b64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    arr[i] = binary.charCodeAt(i);
  }
  return arr;
}
