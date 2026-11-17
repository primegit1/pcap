import { describe, expect, it } from "vitest";
import { decodeAscii } from "./ascii";

/** The original (slow) implementations, kept here as the behavioural reference. */
const referenceWithNewlines = (payload: ArrayBuffer) =>
  Array.from(new Uint8Array(payload))
    .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : b === 10 || b === 13 ? String.fromCharCode(b) : " "))
    .join("");
const referenceWithoutNewlines = (payload: ArrayBuffer) =>
  Array.from(new Uint8Array(payload))
    .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : " "))
    .join("");

describe("decodeAscii", () => {
  it("matches the original implementations on every byte value and on random payloads", () => {
    const all = new Uint8Array(256).map((_, i) => i).buffer;
    expect(decodeAscii(all, true)).toBe(referenceWithNewlines(all));
    expect(decodeAscii(all, false)).toBe(referenceWithoutNewlines(all));

    let seed = 7;
    const rnd = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296;
    for (let n = 0; n < 200; n++) {
      const len = Math.floor(rnd() * 3000);
      const buf = new Uint8Array(len).map(() => Math.floor(rnd() * 256)).buffer;
      expect(decodeAscii(buf, true)).toBe(referenceWithNewlines(buf));
      expect(decodeAscii(buf, false)).toBe(referenceWithoutNewlines(buf));
    }
  });

  it("handles empty and very large payloads and caches per buffer", () => {
    expect(decodeAscii(new ArrayBuffer(0))).toBe("");
    const big = new Uint8Array(500_000).fill(65).buffer;
    expect(decodeAscii(big).length).toBe(500_000);
    expect(decodeAscii(big)).toBe(decodeAscii(big));
  });
});
