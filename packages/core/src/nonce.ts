/**
 * Nonce store for replay protection.
 */

export interface NonceStore {
  has(nonce: string): boolean;
  add(nonce: string): void;
}

export class InMemoryNonceStore implements NonceStore {
  private nonces = new Map<string, number>();
  private readonly ttlMs: number;

  constructor(ttlMs: number = 600_000) {
    this.ttlMs = ttlMs;
  }

  has(nonce: string): boolean {
    this.evict();
    return this.nonces.has(nonce);
  }

  add(nonce: string): void {
    this.evict();
    this.nonces.set(nonce, Date.now());
  }

  private evict(): void {
    const cutoff = Date.now() - this.ttlMs;
    for (const [nonce, timestamp] of this.nonces) {
      if (timestamp < cutoff) {
        this.nonces.delete(nonce);
      }
    }
  }
}
