

/* ───────── Application-layer payload helpers ───────── */

/**
 * Extract the first line (up to \r\n or \n) of a buffer as text.
 */
export function firstLineAsText(buf: ArrayBuffer, maxLen = 200): string {
  const bytes = new Uint8Array(buf.slice(0, maxLen));
  let end = bytes.length;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x0a) { end = i; break; }
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) { end = i; break; }
  }
  const chars: string[] = [];
  for (let i = 0; i < end; i++) {
    const b = bytes[i];
    chars.push(b >= 32 && b <= 126 ? String.fromCharCode(b) : ".");
  }
  return chars.join("");
}


/**
 * Generic raw text summarizer for unknown protocols.
 */
export function summarizeRaw(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 120);
  return text || "";
}
