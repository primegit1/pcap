import { describe, expect, it } from "vitest";
import {
  analyze,
  makePcap,
  tcpFrame,
  tcpSession,
  udpFrame,
  TCP,
  type Frame,
  type Ip4,
} from "../test-utils/pcapBuilder";

const C: Ip4 = [10, 0, 0, 5];
const S: Ip4 = [10, 0, 0, 9];
const ATTACKER: Ip4 = [10, 0, 0, 66];
const T0 = 1_700_000_000;

const titles = (frames: Frame[]) => analyze(makePcap(frames)).findings.map((f) => f.title);
const scanTitle = "Port Scan Activity Observed (Passive Detection)";
const sweepTitle = "Horizontal Port Sweep Observed (Passive Detection)";
const floodTitle = "SYN Flood Pattern Observed (Passive Detection)";

describe("port scan detection", () => {
  it("does not flag a browser opening 15 parallel HTTPS connections to one server", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 15; i++) {
      frames.push(...tcpSession(C, S, 50000 + i, 443, T0 + i * 0.05));
    }
    const t = titles(frames);
    expect(t).not.toContain(scanTitle);
    expect(t).not.toContain(sweepTitle);
  });

  it("flags a real SYN scan of 30 ports within 5 seconds exactly once", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 30; i++) {
      frames.push({ t: T0 + i * (5 / 30), d: tcpFrame(ATTACKER, S, 40000, 1000 + i, TCP.SYN) });
    }
    const findings = analyze(makePcap(frames)).findings.filter((f) => f.title === scanTitle);
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.severity).toBe("High");
    expect(f.affectedIp).toBe("10.0.0.9");
    expect(f.evidence).toContain("1000");
    expect(f.packetIndices!.length).toBeGreaterThan(0);
    expect(f.refsApproximate).toBeFalsy();
  });

  it("does not flag the same 30 ports spread over 10 minutes", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 30; i++) {
      frames.push({ t: T0 + i * 20, d: tcpFrame(ATTACKER, S, 40000, 1000 + i, TCP.SYN) });
    }
    expect(titles(frames)).not.toContain(scanTitle);
  });

  it("flags one port probed on 50 hosts as a horizontal sweep", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 50; i++) {
      frames.push({ t: T0 + i * 0.1, d: tcpFrame(ATTACKER, [10, 0, 1, i + 1], 40000, 445, TCP.SYN) });
    }
    const findings = analyze(makePcap(frames)).findings.filter((f) => f.title === sweepTitle);
    expect(findings).toHaveLength(1);
    expect(findings[0].affectedIp).toBe("10.0.0.66");
    expect(findings[0].evidence).toContain("445");
  });

  it("ignores UDP chatter that the target answers, but flags unanswered UDP probing", () => {
    const answered: Frame[] = [];
    for (let i = 0; i < 30; i++) {
      answered.push({ t: T0 + i * 0.1, d: udpFrame(C, S, 40000, 1000 + i) });
      answered.push({ t: T0 + i * 0.1 + 0.01, d: udpFrame(S, C, 1000 + i, 40000) });
    }
    expect(titles(answered)).not.toContain(scanTitle);

    const unanswered: Frame[] = [];
    for (let i = 0; i < 30; i++) {
      unanswered.push({ t: T0 + i * 0.1, d: udpFrame(ATTACKER, S, 40000, 1000 + i) });
    }
    expect(titles(unanswered)).toContain(scanTitle);
  });
});

describe("SYN flood detection", () => {
  it("does not flag 200 SYNs that the server answers with SYN-ACKs", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 200; i++) {
      const t = T0 + i * 0.01;
      frames.push({ t, d: tcpFrame(C, S, 20000 + i, 80, TCP.SYN) });
      frames.push({ t: t + 0.001, d: tcpFrame(S, C, 80, 20000 + i, TCP.SYN | TCP.ACK) });
    }
    expect(titles(frames)).not.toContain(floodTitle);
  });

  it("flags 200 SYNs with no replies in a short window", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 200; i++) {
      frames.push({ t: T0 + i * 0.01, d: tcpFrame(ATTACKER, S, 20000 + i, 80, TCP.SYN) });
    }
    const f = analyze(makePcap(frames)).findings.filter((x) => x.title === floodTitle);
    expect(f).toHaveLength(1);
    expect(f[0].affectedIp).toBe("10.0.0.9");
    expect(f[0].confidence).toBe("high");
  });

  it("does not flag 100 SYNs spread over hours (normal long-running capture)", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 100; i++) {
      frames.push({ t: T0 + i * 120, d: tcpFrame(C, S, 20000 + i, 80, TCP.SYN) });
    }
    expect(titles(frames)).not.toContain(floodTitle);
  });
});
