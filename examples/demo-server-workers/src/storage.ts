/**
 * Storage implementations for the Workers x428 demo server.
 *
 * KV-backed stores for challenges, tokens, and accepted preconditions
 * enable cross-session state sharing (e.g., Claude Desktop's separate
 * AppBridge and Model sessions map to different Durable Objects, but
 * both read/write the same KV namespace).
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
// KV-backed challenge store
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

export class KvChallengeStore implements ChallengeStore {
  constructor(private kv: KVNamespace, private prefix = "x428:challenge:") {}

  async get(challengeId: string): Promise<ChallengeRecord | null> {
    const raw = await this.kv.get(this.prefix + challengeId);
    if (!raw) return null;
    const data: SerializedChallengeRecord = JSON.parse(raw);
    return {
      ...data,
      privateKey: base64ToUint8Array(data.privateKeyBase64),
    };
  }

  async set(challengeId: string, record: ChallengeRecord, ttlMs?: number): Promise<void> {
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
    await this.kv.delete(this.prefix + challengeId);
  }
}

// ---------------------------------------------------------------------------
// KV-backed token store
// ---------------------------------------------------------------------------

export class KvTokenStore implements TokenStore {
  constructor(private kv: KVNamespace, private prefix = "x428:token:") {}

  async get(cacheKey: string): Promise<AttestationToken | null> {
    const raw = await this.kv.get(this.prefix + cacheKey);
    if (!raw) return null;
    return JSON.parse(raw);
  }

  async set(cacheKey: string, token: AttestationToken): Promise<void> {
    const expiresAt = new Date(token.expiresAt).getTime();
    const ttlSeconds = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000));
    await this.kv.put(this.prefix + cacheKey, JSON.stringify(token), {
      expirationTtl: ttlSeconds,
    });
  }
}

// ---------------------------------------------------------------------------
// KV-backed accepted precondition store
// ---------------------------------------------------------------------------

export class KvAcceptedPreconditionStore implements AcceptedPreconditionStore {
  constructor(private kv: KVNamespace, private prefix = "x428:accepted:", private ttlSeconds = 86400) {}

  async getAccepted(sessionId: string): Promise<Set<string>> {
    const raw = await this.kv.get(this.prefix + sessionId);
    if (!raw) return new Set();
    return new Set(JSON.parse(raw));
  }

  async addAll(sessionId: string, keys: string[]): Promise<void> {
    const existing = await this.getAccepted(sessionId);
    for (const k of keys) existing.add(k);
    await this.kv.put(this.prefix + sessionId, JSON.stringify([...existing]), {
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
