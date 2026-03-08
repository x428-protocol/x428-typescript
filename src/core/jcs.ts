import canonicalize from "canonicalize";

export function jcsCanonical(obj: Record<string, unknown>): string {
  const result = canonicalize(obj);
  if (result === undefined) throw new Error("JCS canonicalization failed");
  return result;
}

export function jcsCanonicalHex(obj: Record<string, unknown>): string {
  const canonical = jcsCanonical(obj);
  const bytes = new TextEncoder().encode(canonical);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function jcsCanonicalBytes(obj: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(jcsCanonical(obj));
}
