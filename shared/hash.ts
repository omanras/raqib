/**
 * SHA-256 as the domain uses it: over the UTF-8 bytes of a string, as 64
 * lowercase hex characters. The domain code takes the hash function as a
 * parameter so the same code runs on the server (node:crypto, synchronous,
 * usable inside a SQLite transaction) and in the browser (Web Crypto,
 * asynchronous). Both produce identical output; tests/unit proves it.
 */
export type Sha256Hex = (text: string) => string;
export type Sha256HexAsync = (text: string) => Promise<string>;

const HEX64 = /^[0-9a-f]{64}$/;

export function isHex64(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Web Crypto SHA-256 (browser, and Node's globalThis.crypto). */
export const webSha256Hex: Sha256HexAsync = async (text) => {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return bytesToHex(new Uint8Array(digest));
};
