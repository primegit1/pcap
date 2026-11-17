/**
 * Fast, memoized "printable ASCII" view of a packet payload.
 *
 * Bytes 0x20-0x7E are kept; everything else becomes a space (CR/LF are kept when
 * `keepNewlines` is true). Several rules decode the same payload, so the result is cached
 * per ArrayBuffer for the lifetime of the packet.
 */
const decoder = new TextDecoder("latin1");
const withNewlines = new WeakMap<ArrayBuffer, string>();
const withoutNewlines = new WeakMap<ArrayBuffer, string>();

export function decodeAscii(payload: ArrayBuffer, keepNewlines = true): string {
  const cache = keepNewlines ? withNewlines : withoutNewlines;
  const hit = cache.get(payload);
  if (hit !== undefined) return hit;

  const bytes = new Uint8Array(payload.byteLength);
  bytes.set(new Uint8Array(payload));
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) continue;
    if (keepNewlines && (b === 10 || b === 13)) continue;
    bytes[i] = 32;
  }
  // After normalization only ASCII remains, so latin1 vs. any other decoding is identical.
  const text = decoder.decode(bytes);
  cache.set(payload, text);
  return text;
}
