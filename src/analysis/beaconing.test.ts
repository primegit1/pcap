import { describe, expect, it } from "vitest";
import {
  analyze,
  ascii,
  makePcap,
  tcpFrame,
  udpFrame,
  TCP,
  type Frame,
  type Ip4,
} from "../test-utils/pcapBuilder";

const C: Ip4 = [10, 0, 0, 5];
const S: Ip4 = [203, 0, 113, 7];
const T0 = 1_700_000_000;
const title = "Possible C2 Beaconing (Regular Callback Interval)";

/** Deterministic pseudo-random generator so the tests are repeatable. */
function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296;
    return s / 4294967296;
  };
}

function connectionAt(t: number, port: number, dstPort: number): Frame[] {
  return [
    { t, d: tcpFrame(C, S, port, dstPort, TCP.SYN) },
    { t: t + 0.05, d: tcpFrame(S, C, dstPort, port, TCP.SYN | TCP.ACK) },
    { t: t + 0.1, d: tcpFrame(C, S, port, dstPort, TCP.PSH | TCP.ACK, ascii("x".repeat(64))) },
  ];
}

describe("beaconing detection", () => {
  it("flags a 60 s beacon with 10% jitter", () => {
    const r = rng(1);
    const frames: Frame[] = [];
    let t = T0;
    for (let i = 0; i < 25; i++) {
      frames.push(...connectionAt(t, 40000 + i, 8443));
      t += 60 * (1 + (r() - 0.5) * 0.2);
    }
    const hits = analyze(makePcap(frames)).findings.filter((f) => f.title === title);
    expect(hits).toHaveLength(1);
    expect(hits[0].affectedIp).toBe("10.0.0.5");
    expect(hits[0].confidence).toBe("high"); // 25 events, tight timing, constant payload size
    expect(hits[0].packetIndices!.length).toBeGreaterThan(0);
  });

  it("does not flag randomly timed browsing", () => {
    const r = rng(7);
    const frames: Frame[] = [];
    let t = T0;
    for (let i = 0; i < 40; i++) {
      frames.push(...connectionAt(t, 40000 + i, 443));
      t += -Math.log(1 - r()) * 60; // exponential gaps: CV ~ 1
    }
    expect(analyze(makePcap(frames)).findings.map((f) => f.title)).not.toContain(title);
  });

  it("does not flag NTP polling every 64 s", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 30; i++) {
      frames.push({ t: T0 + i * 64, d: udpFrame(C, S, 123, 123, new Uint8Array(48)) });
    }
    expect(analyze(makePcap(frames)).findings.map((f) => f.title)).not.toContain(title);
  });

  it("does not flag too-few events", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 6; i++) frames.push(...connectionAt(T0 + i * 60, 40000 + i, 8443));
    expect(analyze(makePcap(frames)).findings.map((f) => f.title)).not.toContain(title);
  });
});
