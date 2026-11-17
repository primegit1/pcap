import type { Packet } from "../types/packets";
import {
  parsePcap,
  pcapTimestampToUs,
  isPcapMagic,
} from "./pcap";
import { parsePcapng, isPcapngMagic } from "./pcapng";
import { parsePacket } from "./index";
import { isSupportedLinkType, linkTypeName, normalizeFrame } from "./linklayer";

export type CaptureFormat = "pcap" | "pcapng";

export interface CaptureInfo {
  format: CaptureFormat;
  /** Frames present in the file (before any were skipped) */
  totalFrames: number;
  /** Frames that were decoded into packets */
  decodedPackets: number;
  /** Frames whose link type is not supported, keyed by link-type name */
  unsupportedLinkTypes: Record<string, number>;
  /** Frames that could not be decoded (too short / unparseable) */
  undecodableFrames: number;
  /** Zero-length records skipped */
  emptyRecords: number;
  truncated: boolean;
  /** Human-readable problems to show the user. Empty when the capture was clean. */
  warnings: string[];
}

export interface DecodedCapture {
  packets: Packet[];
  info: CaptureInfo;
}

/**
 * Identify the capture format from the file's magic bytes (never from the extension).
 */
export function detectCaptureFormat(buffer: ArrayBuffer): CaptureFormat {
  if (buffer.byteLength < 8) {
    throw new Error("File is too small to be a pcap or pcapng capture");
  }
  const magic = new DataView(buffer).getUint32(0, false);
  if (isPcapngMagic(magic)) return "pcapng";
  if (isPcapMagic(magic)) return "pcap";
  throw new Error(
    `Unrecognized capture format (first bytes 0x${magic.toString(16).padStart(8, "0")}). ` +
      "Expected a .pcap or .pcapng file."
  );
}

type Progress = (percent: number, stage: string) => void;

/**
 * Parse and decode a whole capture file into packets.
 * Shared by the analysis worker and the tests.
 */
export function decodeCapture(buffer: ArrayBuffer, onProgress?: Progress): DecodedCapture {
  const format = detectCaptureFormat(buffer);
  onProgress?.(0, `Reading ${format.toUpperCase()} structure`);

  interface RawFrame {
    data: ArrayBuffer;
    timestampUs: number;
    linkType: number;
  }
  const frames: RawFrame[] = [];
  const warnings: string[] = [];
  let emptyRecords = 0;
  let truncated: boolean;

  if (format === "pcapng") {
    const ng = parsePcapng(buffer);
    truncated = ng.truncated;
    for (const p of ng.packets) {
      frames.push({ data: p.packetData, timestampUs: p.timestampUs, linkType: p.linkType });
    }
  } else {
    const pc = parsePcap(buffer);
    truncated = pc.truncated;
    emptyRecords = pc.emptyRecords;
    for (const rec of pc.packets) {
      frames.push({
        data: rec.data,
        timestampUs: pcapTimestampToUs(rec.header, pc.globalHeader.isMicrosecond),
        linkType: pc.linkType,
      });
    }
    if (pc.stoppedEarly) warnings.push(pc.stoppedEarly);
  }

  if (truncated) {
    warnings.push("The capture file ends in the middle of a record; the final partial packet was ignored.");
  }

  onProgress?.(25, `Decoding ${frames.length.toLocaleString()} frames`);

  const packets: Packet[] = [];
  const unsupported: Record<string, number> = {};
  let undecodable = 0;
  const step = Math.max(1, Math.floor(frames.length / 50));

  for (let i = 0; i < frames.length; i++) {
    const frame = frames[i];
    if (!isSupportedLinkType(frame.linkType)) {
      const name = linkTypeName(frame.linkType);
      unsupported[name] = (unsupported[name] ?? 0) + 1;
      continue;
    }
    const normalized = normalizeFrame(frame.data, frame.linkType);
    const packet = normalized ? parsePacket(normalized, i, frame.timestampUs) : null;
    if (packet) {
      packet.linkType = frame.linkType;
      packets.push(packet);
    } else {
      undecodable++;
    }
    if (i % step === 0) {
      onProgress?.(25 + Math.floor((i / frames.length) * 75), `Decoding frames (${i + 1}/${frames.length})`);
    }
  }

  for (const [name, count] of Object.entries(unsupported)) {
    warnings.push(`${count.toLocaleString()} frame(s) skipped: unsupported link type "${name}".`);
  }
  if (undecodable > 0) {
    warnings.push(`${undecodable.toLocaleString()} frame(s) were too short or malformed to decode.`);
  }
  if (emptyRecords > 0) {
    warnings.push(`${emptyRecords.toLocaleString()} zero-length record(s) were skipped.`);
  }

  return {
    packets,
    info: {
      format,
      totalFrames: frames.length + emptyRecords,
      decodedPackets: packets.length,
      unsupportedLinkTypes: unsupported,
      undecodableFrames: undecodable,
      emptyRecords,
      truncated,
      warnings,
    },
  };
}
