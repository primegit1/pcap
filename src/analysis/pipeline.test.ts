import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { analyzePackets, combineAnalysisResults, mergeFindings } from "./index";
import { detectLargeTransfer } from "./security-rules/network";
import { buildFlows } from "./flow-analysis";
import { decodeCapture } from "../parsers/capture";
import {
  analyze,
  makePcap,
  tcpFrame,
  tcpSession,
  TCP,
  udpFrame,
  type Frame,
  type Ip4,
} from "../test-utils/pcapBuilder";
import type { FlowRecord, SecurityFinding } from "../types/analysis";
import type { Packet } from "../types/packets";

const C: Ip4 = [10, 0, 0, 5];
const S: Ip4 = [10, 0, 0, 9];
const T0 = 1_700_000_000;

function loadBundledCapture() {
  const b = readFileSync(new URL("../../public/test-traffic.pcap", import.meta.url));
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

describe("large captures and ordering", () => {
  it("analyzes 300,000 packets without a RangeError (no Math.max spread)", () => {
    const base = decodeCapture(makePcap([{ t: T0, d: udpFrame(C, S, 40000, 5000, new Uint8Array(10)) }]))
      .packets[0];
    const packets: Packet[] = Array.from({ length: 300_000 }, (_, i) => ({
      ...base,
      index: i,
      timestampUs: T0 * 1_000_000 + i * 1000,
    }));
    const result = analyzePackets(packets, "big.pcap");
    expect(result.summary.totalPackets).toBe(300_000);
    expect(result.summary.durationUs).toBe(299_999 * 1000);
  }, 120_000);

  it("computes duration and timeline correctly when packets are not in time order", () => {
    const frames: Frame[] = [];
    for (let i = 0; i < 400; i++) frames.push({ t: T0 + i, d: udpFrame(C, S, 40000, 5000) });
    const { packets } = decodeCapture(makePcap(frames));
    // Reverse the order, as a merged / multi-interface capture could be.
    const shuffled = [...packets].reverse();
    const result = analyzePackets(shuffled, "unsorted.pcap");
    expect(result.summary.durationUs).toBe(399 * 1_000_000);
    const buckets = result.summary.timelineBuckets;
    expect(buckets.length).toBeGreaterThan(0);
    expect(buckets.reduce((s, b) => s + b.packetCount, 0)).toBe(400);
    expect(buckets[0].timestampUs).toBe(T0 * 1_000_000);
  });

  it("combines files in time order with unique packet indices", () => {
    const a = analyze(makePcap(tcpSession(C, S, 50000, 443, T0 + 100)), "a.pcap");
    const b = analyze(makePcap(tcpSession(C, S, 50001, 443, T0)), "b.pcap");
    const combined = combineAnalysisResults([a, b]);
    const idx = combined.packets.map((p) => p.index);
    expect(new Set(idx).size).toBe(idx.length);
    expect(idx).toEqual(idx.map((_, i) => i));
    const times = combined.packets.map((p) => p.timestampUs);
    expect([...times].sort((x, y) => x - y)).toEqual(times);
    expect(combined.fileName).toBe("a.pcap, b.pcap");
    expect(combined.summary.totalPackets).toBe(a.summary.totalPackets + b.summary.totalPackets);
  });
});

describe("findings model", () => {
  it("assigns unique IDs across a full analysis of the bundled capture", () => {
    const { packets } = decodeCapture(loadBundledCapture());
    const result = analyzePackets(packets, "test-traffic.pcap");
    const ids = result.findings.map((f) => f.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("findings carry capture-time timestamps and packet references that point at real packets", () => {
    const { packets } = decodeCapture(loadBundledCapture());
    const result = analyzePackets(packets, "test-traffic.pcap");
    const valid = new Set(packets.map((p) => p.index));
    const first = Math.min(...packets.map((p) => p.timestampUs));
    const last = Math.max(...packets.map((p) => p.timestampUs));
    for (const f of result.findings) {
      expect(f.confidence).toMatch(/^(low|medium|high)$/);
      expect(f.occurrences).toBeGreaterThanOrEqual(1);
      expect(f.firstSeenUs).toBeGreaterThanOrEqual(first);
      expect(f.lastSeenUs).toBeLessThanOrEqual(last);
      // timestamp is capture time (ms), not analysis time
      expect(f.timestamp).toBe(Math.floor(f.firstSeenUs! / 1000));
      for (const i of f.packetIndices ?? []) expect(valid.has(i)).toBe(true);
    }
  });

  it("merges duplicate findings instead of dropping them, and keeps distinct dedupKeys apart", () => {
    const mk = (over: Partial<SecurityFinding>): SecurityFinding => ({
      id: "x",
      title: "T",
      severity: "High",
      description: "d",
      recommendation: "r",
      evidence: "e1",
      affectedIp: "1.1.1.1",
      category: "Network",
      timestamp: 0,
      occurrences: 1,
      packetIndices: [1],
      firstSeenUs: 100,
      lastSeenUs: 200,
      ...over,
    });
    const merged = mergeFindings([
      mk({}),
      mk({ evidence: "e2", packetIndices: [2], firstSeenUs: 50, lastSeenUs: 300 }),
      mk({ dedupKey: "other" }),
    ]);
    expect(merged).toHaveLength(2);
    const m = merged.find((f) => !f.dedupKey)!;
    expect(m.occurrences).toBe(2);
    expect(m.evidence).toContain("e1");
    expect(m.evidence).toContain("e2");
    expect(m.packetIndices).toEqual([1, 2]);
    expect(m.firstSeenUs).toBe(50);
    expect(m.lastSeenUs).toBe(300);
  });

  it("keeps the bundled-capture findings stable (regression)", () => {
    const { packets } = decodeCapture(loadBundledCapture());
    const result = analyzePackets(packets, "test-traffic.pcap");
    const rows = result.findings.map((f) => `${f.severity}|${f.title}|${f.affectedIp}`).sort();
    expect(rows).toMatchSnapshot();
  });
});

describe("bidirectional flows", () => {
  it("represents one TCP connection as one flow with the SYN sender as initiator", () => {
    const frames = tcpSession(C, S, 50000, 443, T0, new Uint8Array(30), new Uint8Array(500));
    const { packets } = decodeCapture(makePcap(frames));
    const flows = buildFlows(packets);
    expect(flows).toHaveLength(1);
    const f = flows[0];
    expect(f.srcIp).toBe("10.0.0.5");
    expect(f.srcPort).toBe(50000);
    expect(f.dstIp).toBe("10.0.0.9");
    expect(f.dstPort).toBe(443);
    expect(f.synSeen).toBe(true);
    expect(f.synAckSeen).toBe(true);
    expect(f.initiatorPackets).toBe(3); // SYN, ACK, client data
    expect(f.responderPackets).toBe(2); // SYN-ACK, server data
    expect(f.packetCount).toBe(5);
    expect(f.byteCount).toBe(f.initiatorBytes + f.responderBytes);
    expect(f.responderBytes).toBeGreaterThan(f.initiatorBytes - 100);
  });

  it("orients a flow captured mid-stream by the well-known port", () => {
    // Only server→client packets were captured (no SYN).
    const frames: Frame[] = [
      { t: T0, d: tcpFrame(S, C, 443, 50000, TCP.PSH | TCP.ACK, new Uint8Array(10)) },
      { t: T0 + 0.1, d: tcpFrame(C, S, 50000, 443, TCP.ACK) },
    ];
    const flows = buildFlows(decodeCapture(makePcap(frames)).packets);
    expect(flows).toHaveLength(1);
    expect(flows[0].dstPort).toBe(443);
    expect(flows[0].srcIp).toBe("10.0.0.5");
  });

  it("describes a 12 MB download from the sender's point of view", () => {
    const mb = 1024 * 1024;
    const flow: FlowRecord = {
      id: "6|10.0.0.5|50000|10.0.0.9|443",
      srcIp: "10.0.0.5",
      dstIp: "10.0.0.9",
      srcPort: 50000,
      dstPort: 443,
      ipProtocol: 6,
      appProtocol: "HTTPS" as FlowRecord["appProtocol"],
      packetCount: 9000,
      byteCount: 12 * mb + 2000,
      initiatorPackets: 100,
      responderPackets: 8900,
      initiatorBytes: 2000,
      responderBytes: 12 * mb,
      synSeen: true,
      synAckSeen: true,
      finSeen: false,
      rstSeen: false,
      startTimeUs: 1,
      endTimeUs: 2,
    };
    const [download] = detectLargeTransfer([flow]);
    expect(download.affectedIp).toBe("10.0.0.9"); // the server SENT the data
    expect(download.description).toMatch(/download by the initiator/);
    expect(download.flowIds).toEqual([flow.id]);

    const [upload] = detectLargeTransfer([
      { ...flow, initiatorBytes: 12 * mb, responderBytes: 2000, initiatorPackets: 8900, responderPackets: 100 },
    ]);
    expect(upload.affectedIp).toBe("10.0.0.5");
    expect(upload.description).toMatch(/upload from the initiator/);
  });
});
