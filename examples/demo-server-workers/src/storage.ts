/**
 * SQLite-backed storage for x428 state in Durable Objects.
 *
 * Uses the DO's built-in SQLite via ctx.storage.sql.exec().
 * Tables are created idempotently (IF NOT EXISTS) in initTables().
 */

import type { NonceStore } from "@x428/core";
import type { AttestationToken, PreconditionChallenge } from "@x428/core";

/** SQL executor interface matching DO's ctx.storage.sql */
export interface SqlStorage {
  exec(query: string, ...bindings: unknown[]): { toArray(): Record<string, unknown>[]; one(): Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Table initialization
// ---------------------------------------------------------------------------

export function initTables(sql: SqlStorage): void {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS nonces (
      nonce TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );
  `);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS challenges (
      challenge_id TEXT PRIMARY KEY,
      challenge_json TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS tokens (
      cache_key TEXT PRIMARY KEY,
      token_json TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `);
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

// ---------------------------------------------------------------------------
// Nonce store — implements NonceStore from @x428/core
// ---------------------------------------------------------------------------

export class SqliteNonceStore implements NonceStore {
  constructor(private sql: SqlStorage, private ttlMs: number = 600_000) {}

  has(nonce: string): boolean {
    this.evict();
    const rows = this.sql.exec(
      "SELECT 1 FROM nonces WHERE nonce = ? AND expires_at > ?;",
      nonce, Date.now(),
    ).toArray();
    return rows.length > 0;
  }

  add(nonce: string): void {
    this.evict();
    this.sql.exec(
      "INSERT OR IGNORE INTO nonces (nonce, expires_at) VALUES (?, ?);",
      nonce, Date.now() + this.ttlMs,
    );
  }

  private evict(): void {
    this.sql.exec("DELETE FROM nonces WHERE expires_at <= ?;", Date.now());
  }
}

// ---------------------------------------------------------------------------
// Challenge store — pending challenges keyed by challengeId
// ---------------------------------------------------------------------------

export class SqliteChallengeStore {
  constructor(private sql: SqlStorage) {}

  get(challengeId: string): PreconditionChallenge | null {
    this.evict();
    const rows = this.sql.exec(
      "SELECT challenge_json FROM challenges WHERE challenge_id = ? AND expires_at > ?;",
      challengeId, Date.now(),
    ).toArray();
    if (rows.length === 0) return null;
    return JSON.parse(rows[0].challenge_json as string);
  }

  set(challengeId: string, challenge: PreconditionChallenge, ttlMs: number = 300_000): void {
    this.evict();
    this.sql.exec(
      "INSERT OR REPLACE INTO challenges (challenge_id, challenge_json, expires_at) VALUES (?, ?, ?);",
      challengeId, JSON.stringify(challenge), Date.now() + ttlMs,
    );
  }

  delete(challengeId: string): void {
    this.sql.exec("DELETE FROM challenges WHERE challenge_id = ?;", challengeId);
  }

  private evict(): void {
    this.sql.exec("DELETE FROM challenges WHERE expires_at <= ?;", Date.now());
  }
}

// ---------------------------------------------------------------------------
// Token store — cached attestation tokens keyed by "sessionId:resourceUri"
// ---------------------------------------------------------------------------

export class SqliteTokenStore {
  constructor(private sql: SqlStorage) {}

  get(cacheKey: string): AttestationToken | null {
    this.evict();
    const rows = this.sql.exec(
      "SELECT token_json FROM tokens WHERE cache_key = ? AND expires_at > ?;",
      cacheKey, Date.now(),
    ).toArray();
    if (rows.length === 0) return null;
    return JSON.parse(rows[0].token_json as string);
  }

  set(cacheKey: string, token: AttestationToken): void {
    this.evict();
    const expiresAt = new Date(token.expiresAt).getTime();
    this.sql.exec(
      "INSERT OR REPLACE INTO tokens (cache_key, token_json, expires_at) VALUES (?, ?, ?);",
      cacheKey, JSON.stringify(token), expiresAt,
    );
  }

  private evict(): void {
    this.sql.exec("DELETE FROM tokens WHERE expires_at <= ?;", Date.now());
  }
}

// ---------------------------------------------------------------------------
// Attestation audit log — append-only compliance record
// ---------------------------------------------------------------------------

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
