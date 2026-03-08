/**
 * Nonce store for replay protection.
 */

export interface NonceStore {
  has(nonce: string): boolean;
  add(nonce: string): void;
}

export class InMemoryNonceStore implements NonceStore {
  private nonces = new Set<string>();

  has(nonce: string): boolean {
    return this.nonces.has(nonce);
  }

  add(nonce: string): void {
    this.nonces.add(nonce);
  }
}
