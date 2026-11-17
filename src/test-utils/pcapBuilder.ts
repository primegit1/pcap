/**
 * Helpers for building synthetic captures in memory, so detection rules and
 * parsers can be tested without binary fixtures.
 */
import { decodeCapture, type CaptureFormat } from "../parsers/capture";
import { analyzePackets } from "../analysis";
import type { AnalysisResult } from "../types/analysis";

export type Ip4 = [number, number, number, number];

export interface Frame {
  /** Seconds since epoch (fractions allowed) */
  t: number;
  d: Uint8Array;
}

export const TCP = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 } as const;

function ipv4Header(b: Uint8Array, v: DataView, src: Ip4, dst: Ip4, proto: number, l4Len: number) {
  b[14] = 0x45;
  v.setUint16(16, 20 + l4Len);
  b[22] = 64;
  b[23] = proto;
  b.set(src, 26);
  b.set(dst, 30);
}

/** Ethernet + IPv4 + TCP frame. */
export function tcpFrame(
  src: Ip4,
  dst: Ip4,
  srcPort: number,
  dstPort: number,
  flags: number,
  payload: Uint8Array = new Uint8Array(0)
): Uint8Array {
  const b = new Uint8Array(14 + 20 + 20 + payload.length);
  const v = new DataView(b.buffer);
  b.set([2, 0, 0, 0, 0, 1], 0);
  b.set([2, 0, 0, 0, 0, 2], 6);
  v.setUint16(12, 0x0800);
  ipv4Header(b, v, src, dst, 6, 20 + payload.length);
  v.setUint16(34, srcPort);
  v.setUint16(36, dstPort);
  v.setUint32(38, 1);
  v.setUint32(42, 1);
  b[46] = 5 << 4;
  b[47] = flags;
  v.setUint16(48, 65535);
  b.set(payload, 54);
  return b;
}

/** Ethernet + IPv4 + UDP frame. */
export function udpFrame(
  src: Ip4,
  dst: Ip4,
  srcPort: number,
  dstPort: number,
  payload: Uint8Array = new Uint8Array(0)
): Uint8Array {
  const b = new Uint8Array(14 + 20 + 8 + payload.length);
  const v = new DataView(b.buffer);
  b.set([2, 0, 0, 0, 0, 1], 0);
  b.set([2, 0, 0, 0, 0, 2], 6);
  v.setUint16(12, 0x0800);
  ipv4Header(b, v, src, dst, 17, 8 + payload.length);
  v.setUint16(34, srcPort);
  v.setUint16(36, dstPort);
  v.setUint16(38, 8 + payload.length);
  b.set(payload, 42);
  return b;
}

/** Ethernet + IPv4 + ICMP echo request/reply. */
export function icmpFrame(src: Ip4, dst: Ip4, type = 8): Uint8Array {
  const b = new Uint8Array(14 + 20 + 8);
  const v = new DataView(b.buffer);
  b.set([2, 0, 0, 0, 0, 1], 0);
  b.set([2, 0, 0, 0, 0, 2], 6);
  v.setUint16(12, 0x0800);
  ipv4Header(b, v, src, dst, 1, 8);
  b[34] = type;
  return b;
}

export function ascii(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function makePcap(
  frames: Frame[],
  opts: { littleEndian?: boolean; nanosecond?: boolean; linkType?: number } = {}
): ArrayBuffer {
  const le = opts.littleEndian ?? true;
  const nano = opts.nanosecond ?? false;
  const total = 24 + frames.reduce((s, f) => s + 16 + f.d.length, 0);
  const buf = new ArrayBuffer(total);
  const v = new DataView(buf);
  // Write the magic so that a big-endian read of the file bytes gives the canonical value
  // for native order, or its swapped form for the opposite order.
  const magic = nano ? 0xa1b23c4d : 0xa1b2c3d4;
  v.setUint32(0, magic, le);
  v.setUint16(4, 2, le);
  v.setUint16(6, 4, le);
  v.setUint32(16, 65535, le);
  v.setUint32(20, opts.linkType ?? 1, le);
  let o = 24;
  for (const f of frames) {
    // Work in integer microseconds: epoch seconds as doubles can't hold nanoseconds exactly.
    const us = Math.round(f.t * 1e6);
    const sec = Math.floor(us / 1e6);
    const frac = (us % 1e6) * (nano ? 1000 : 1);
    v.setUint32(o, sec, le);
    v.setUint32(o + 4, frac, le);
    v.setUint32(o + 8, f.d.length, le);
    v.setUint32(o + 12, f.d.length, le);
    new Uint8Array(buf, o + 16, f.d.length).set(f.d);
    o += 16 + f.d.length;
  }
  return buf;
}

export function makePcapng(
  frames: Frame[],
  opts: { littleEndian?: boolean; tsresol?: number; linkType?: number; sections?: number } = {}
): ArrayBuffer {
  const le = opts.littleEndian ?? true;
  const pad = (n: number) => (n + 3) & ~3;
  const sections = opts.sections ?? 1;
  const tsresol = opts.tsresol; // raw if_tsresol byte (e.g. 9 => nanoseconds)
  const idbLen = 20 + (tsresol !== undefined ? 8 + 4 : 0);
  const shbLen = 28;
  const perSection = Math.ceil(frames.length / sections);

  const chunks: Frame[][] = [];
  for (let i = 0; i < sections; i++) chunks.push(frames.slice(i * perSection, (i + 1) * perSection));

  const size = chunks.reduce(
    (s, c) => s + shbLen + idbLen + c.reduce((a, f) => a + 32 + pad(f.d.length), 0),
    0
  );
  const buf = new ArrayBuffer(size);
  const v = new DataView(buf);
  let o = 0;

  for (const chunk of chunks) {
    // Section Header Block
    v.setUint32(o, 0x0a0d0d0a, le);
    v.setUint32(o + 4, shbLen, le);
    v.setUint32(o + 8, 0x1a2b3c4d, le);
    v.setUint16(o + 12, 1, le);
    v.setUint16(o + 14, 0, le);
    v.setUint32(o + 16, 0xffffffff, le);
    v.setUint32(o + 20, 0xffffffff, le);
    v.setUint32(o + 24, shbLen, le);
    o += shbLen;

    // Interface Description Block (+ optional if_tsresol)
    v.setUint32(o, 1, le);
    v.setUint32(o + 4, idbLen, le);
    v.setUint16(o + 8, opts.linkType ?? 1, le);
    v.setUint32(o + 12, 0, le);
    if (tsresol !== undefined) {
      v.setUint16(o + 16, 9, le); // option code if_tsresol
      v.setUint16(o + 18, 1, le); // length
      v.setUint8(o + 20, tsresol);
      // 3 bytes of padding, then opt_endofopt (code 0, len 0)
    }
    v.setUint32(o + idbLen - 4, idbLen, le);
    o += idbLen;

    const ticksPerSecond = tsresol === undefined ? 1e6 : Math.pow(10, tsresol & 0x7f);
    for (const f of chunk) {
      const bl = 32 + pad(f.d.length);
      const ticks = BigInt(Math.round(f.t * 1e6)) * BigInt(ticksPerSecond) / 1_000_000n;
      v.setUint32(o, 6, le);
      v.setUint32(o + 4, bl, le);
      v.setUint32(o + 8, 0, le);
      v.setUint32(o + 12, Number(ticks >> 32n), le);
      v.setUint32(o + 16, Number(ticks & 0xffffffffn), le);
      v.setUint32(o + 20, f.d.length, le);
      v.setUint32(o + 24, f.d.length, le);
      new Uint8Array(buf, o + 28, f.d.length).set(f.d);
      v.setUint32(o + bl - 4, bl, le);
      o += bl;
    }
  }
  return buf;
}

/** Decode and analyze a capture buffer, as the app does. */
export function analyze(buffer: ArrayBuffer, fileName = "synthetic.pcap"): AnalysisResult {
  const { packets } = decodeCapture(buffer);
  return analyzePackets(packets, fileName);
}

export function decode(buffer: ArrayBuffer, _format?: CaptureFormat) {
  return decodeCapture(buffer);
}

/** A simple client/server TCP session: SYN, SYN-ACK, ACK, then one data segment each way. */
export function tcpSession(
  client: Ip4,
  server: Ip4,
  clientPort: number,
  serverPort: number,
  t0: number,
  clientPayload = new Uint8Array(0),
  serverPayload = new Uint8Array(100)
): Frame[] {
  const f: Frame[] = [
    { t: t0, d: tcpFrame(client, server, clientPort, serverPort, TCP.SYN) },
    { t: t0 + 0.001, d: tcpFrame(server, client, serverPort, clientPort, TCP.SYN | TCP.ACK) },
    { t: t0 + 0.002, d: tcpFrame(client, server, clientPort, serverPort, TCP.ACK) },
  ];
  if (clientPayload.length) {
    f.push({ t: t0 + 0.003, d: tcpFrame(client, server, clientPort, serverPort, TCP.PSH | TCP.ACK, clientPayload) });
  }
  f.push({ t: t0 + 0.004, d: tcpFrame(server, client, serverPort, clientPort, TCP.PSH | TCP.ACK, serverPayload) });
  return f;
}
