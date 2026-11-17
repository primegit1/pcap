import { describe, expect, it } from "vitest";
import { decodeCapture, detectCaptureFormat } from "./capture";
import {
  makePcap,
  makePcapng,
  tcpFrame,
  tcpSession,
  TCP,
  type Frame,
  type Ip4,
} from "../test-utils/pcapBuilder";
import { captureSizeWarning, describeCaptureSizeProblem, MAX_CAPTURE_BYTES } from "../utils/limits";

const C: Ip4 = [10, 0, 0, 5];
const S: Ip4 = [10, 0, 0, 9];
const T0 = 1_700_000_000;

function sampleFrames(): Frame[] {
  return tcpSession(C, S, 50000, 443, T0, new Uint8Array(20), new Uint8Array(100));
}

describe("format detection", () => {
  it("sniffs magic bytes, not file names", () => {
    expect(detectCaptureFormat(makePcap(sampleFrames()))).toBe("pcap");
    expect(detectCaptureFormat(makePcapng(sampleFrames()))).toBe("pcapng");
  });

  it("rejects unknown files with a clear message", () => {
    const junk = new Uint8Array(64).fill(7).buffer;
    expect(() => detectCaptureFormat(junk)).toThrow(/Unrecognized capture format/);
    expect(() => detectCaptureFormat(new ArrayBuffer(3))).toThrow(/too small/);
  });
});

describe("pcapng", () => {
  const frames = sampleFrames();

  it.each([
    ["little-endian", true],
    ["big-endian", false],
  ])("parses %s files", (_name, le) => {
    const { packets, info } = decodeCapture(makePcapng(frames, { littleEndian: le }));
    expect(info.format).toBe("pcapng");
    expect(packets).toHaveLength(frames.length);
    expect(packets[0].timestampUs).toBe(T0 * 1_000_000);
    expect(packets[1].timestampUs - packets[0].timestampUs).toBe(1000);
    expect(packets[0].ip?.srcIp).toBe("10.0.0.5");
  });

  it("honors if_tsresol (nanosecond interfaces)", () => {
    const { packets } = decodeCapture(makePcapng(frames, { tsresol: 9 }));
    expect(packets).toHaveLength(frames.length);
    // Regression: the IDB options used to be read at the wrong offset, so nanosecond
    // timestamps were interpreted as microseconds (1000x too large).
    expect(packets[0].timestampUs).toBe(T0 * 1_000_000);
    expect(packets[4].timestampUs - packets[0].timestampUs).toBe(4000);
  });

  it("tracks interfaces per section in multi-section files", () => {
    const { packets } = decodeCapture(makePcapng(frames, { sections: 2, tsresol: 9 }));
    expect(packets).toHaveLength(frames.length);
    expect(packets.every((p) => p.timestampUs > T0 * 1_000_000 - 1)).toBe(true);
    expect(packets.every((p) => p.timestampUs < (T0 + 1) * 1_000_000)).toBe(true);
  });

  it("tolerates a truncated final block but reports it", () => {
    const buf = makePcapng(frames);
    const { packets, info } = decodeCapture(buf.slice(0, buf.byteLength - 10));
    expect(packets).toHaveLength(frames.length - 1);
    expect(info.truncated).toBe(true);
    expect(info.warnings.join(" ")).toMatch(/ends in the middle/);
  });

  it("throws on a block length that is not a multiple of 4", () => {
    const buf = makePcapng(frames);
    // First EPB starts after SHB (28) + IDB (20); its length field is at +4.
    new DataView(buf).setUint32(28 + 20 + 4, 33, true);
    expect(() => decodeCapture(buf)).toThrow(/Malformed pcapng block/);
  });

  it("throws on mismatched leading/trailing block lengths", () => {
    const buf = makePcapng(frames);
    const v = new DataView(buf);
    const epbLen = v.getUint32(28 + 20 + 4, true);
    v.setUint32(28 + 20 + epbLen - 4, epbLen + 4, true);
    expect(() => decodeCapture(buf)).toThrow(/trailing length/);
  });
});

describe("pcap", () => {
  const frames = sampleFrames();

  it.each([
    ["native microsecond", { littleEndian: true, nanosecond: false }],
    ["swapped microsecond", { littleEndian: false, nanosecond: false }],
    ["native nanosecond", { littleEndian: true, nanosecond: true }],
    ["swapped nanosecond", { littleEndian: false, nanosecond: true }],
  ])("parses %s files", (_name, opts) => {
    const { packets } = decodeCapture(makePcap(frames, opts));
    expect(packets).toHaveLength(frames.length);
    expect(packets[0].timestampUs).toBe(T0 * 1_000_000);
    expect(packets[4].timestampUs - packets[0].timestampUs).toBe(4000);
  });

  it("reports a truncated capture instead of silently dropping data", () => {
    const buf = makePcap(frames);
    const { packets, info } = decodeCapture(buf.slice(0, buf.byteLength - 5));
    expect(packets).toHaveLength(frames.length - 1);
    expect(info.truncated).toBe(true);
  });

  it("stops with a warning when a record header is implausible", () => {
    const buf = makePcap(frames);
    // Corrupt the 2nd record's included length.
    const firstLen = frames[0].d.length;
    new DataView(buf).setUint32(24 + 16 + firstLen + 8, 0x7fffffff, true);
    const { packets, info } = decodeCapture(buf);
    expect(packets).toHaveLength(1);
    expect(info.warnings.join(" ")).toMatch(/corrupt/);
  });

  it("counts zero-length records", () => {
    const withEmpty: Frame[] = [frames[0], { t: T0 + 1, d: new Uint8Array(0) }, frames[1]];
    const { packets, info } = decodeCapture(makePcap(withEmpty));
    expect(packets).toHaveLength(2);
    expect(info.emptyRecords).toBe(1);
  });

  it("keeps large frames up to the snaplen instead of silently skipping them", () => {
    const big = new Uint8Array(65_000);
    big[12] = 0x88; // non-IP EtherType (local experimental)
    big[13] = 0xb5;
    const { packets, info } = decodeCapture(makePcap([{ t: T0, d: big }]));
    expect(info.warnings).toEqual([]);
    expect(packets).toHaveLength(1);
    expect(packets[0].length).toBe(65_000);
  });
});

describe("link types", () => {
  const eth = tcpFrame(C, S, 50000, 443, TCP.SYN);
  const l3 = eth.slice(14);
  const cases: [string, number, Uint8Array][] = [
    ["raw IP", 101, l3],
    ["raw IPv4", 228, l3],
    ["BSD loopback (NULL)", 0, Uint8Array.from([2, 0, 0, 0, ...l3])],
    ["OpenBSD loopback", 108, Uint8Array.from([0, 0, 0, 2, ...l3])],
    [
      "Linux cooked SLL",
      113,
      Uint8Array.from([0, 0, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00, ...l3]),
    ],
    [
      "Linux cooked SLL2",
      276,
      Uint8Array.from([0x08, 0x00, 0, 0, 0, 0, 0, 1, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, ...l3]),
    ],
  ];

  it.each(cases)("decodes %s captures", (_name, linkType, data) => {
    for (const buf of [
      makePcap([{ t: T0, d: data }], { linkType }),
      makePcapng([{ t: T0, d: data }], { linkType }),
    ]) {
      const { packets, info } = decodeCapture(buf);
      expect(info.warnings).toEqual([]);
      expect(packets).toHaveLength(1);
      expect(packets[0].ip?.srcIp).toBe("10.0.0.5");
      expect(packets[0].ip?.dstIp).toBe("10.0.0.9");
      expect(packets[0].linkType).toBe(linkType);
      expect(packets[0].transport && "dstPort" in packets[0].transport && packets[0].transport.dstPort).toBe(443);
    }
  });

  it("uses the SLL source MAC", () => {
    const sll = cases.find((c) => c[1] === 113)!;
    const { packets } = decodeCapture(makePcap([{ t: T0, d: sll[2] }], { linkType: 113 }));
    expect(packets[0].ethernet?.srcMac).toBe("01:02:03:04:05:06");
  });

  it("warns (with a count) about unsupported link types instead of producing garbage", () => {
    const frames = [
      { t: T0, d: new Uint8Array(40).fill(1) },
      { t: T0 + 1, d: new Uint8Array(40).fill(2) },
    ];
    const { packets, info } = decodeCapture(makePcap(frames, { linkType: 105 }));
    expect(packets).toHaveLength(0);
    expect(info.warnings.join(" ")).toMatch(/2 frame\(s\) skipped: unsupported link type "IEEE 802\.11 Wi-Fi"/);
  });
});

describe("size limits", () => {
  it("rejects files over the limit and warns on big ones", () => {
    expect(describeCaptureSizeProblem("a.pcap", MAX_CAPTURE_BYTES + 1)).toMatch(/exceeds/);
    expect(describeCaptureSizeProblem("a.pcap", 1024)).toBeNull();
    expect(captureSizeWarning(150 * 1024 * 1024)).toMatch(/Large capture/);
    expect(captureSizeWarning(1024)).toBeNull();
  });
});
