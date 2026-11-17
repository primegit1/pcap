import type { PcapGlobalHeader, PcapPacketHeader } from "../types/packets";

/**
 * PCAP magic numbers, as read big-endian from the first four bytes of the file.
 *   a1b2c3d4 = file written in the reader's... "native" order, microsecond timestamps
 *   a1b23c4d = native order, nanosecond timestamps
 *   d4c3b2a1 = byte-swapped, microsecond
 *   4d3cb2a1 = byte-swapped, nanosecond
 */
export const PCAP_MAGIC_MICRO = 0xa1b2c3d4;
export const PCAP_MAGIC_NANO = 0xa1b23c4d;
export const PCAP_MAGIC_MICRO_SWAPPED = 0xd4c3b2a1;
export const PCAP_MAGIC_NANO_SWAPPED = 0x4d3cb2a1;

/** Size of PCAP global header (24 bytes) */
const GLOBAL_HEADER_SIZE = 24;
/** Size of PCAP packet header (16 bytes) */
const PACKET_HEADER_SIZE = 16;
/** Absolute upper bound for a single captured packet (guards against corrupt headers). */
const MAX_PACKET_BYTES = 16 * 1024 * 1024;

export interface PcapRecord {
  header: PcapPacketHeader;
  /** A copy of just this packet's captured bytes */
  data: ArrayBuffer;
}

export interface PcapParseResult {
  globalHeader: PcapGlobalHeader;
  /** LINKTYPE_* value (FCS/flag bits masked off) */
  linkType: number;
  packets: PcapRecord[];
  /** Zero-length records that were skipped */
  emptyRecords: number;
  /** True when the file ended in the middle of a record */
  truncated: boolean;
  /** Set when parsing stopped early because a record header was implausible */
  stoppedEarly: string | null;
}

export function isPcapMagic(magic: number): boolean {
  return (
    magic === PCAP_MAGIC_MICRO ||
    magic === PCAP_MAGIC_NANO ||
    magic === PCAP_MAGIC_MICRO_SWAPPED ||
    magic === PCAP_MAGIC_NANO_SWAPPED
  );
}

/**
 * Parse the 24-byte PCAP global header.
 */
export function parsePcapGlobalHeader(view: DataView, offset: number): PcapGlobalHeader {
  const magicNumber = view.getUint32(offset, false);

  let swapped: boolean;
  let isMicrosecond: boolean;

  switch (magicNumber) {
    case PCAP_MAGIC_MICRO:
      swapped = false;
      isMicrosecond = true;
      break;
    case PCAP_MAGIC_NANO:
      swapped = false;
      isMicrosecond = false;
      break;
    case PCAP_MAGIC_MICRO_SWAPPED:
      swapped = true;
      isMicrosecond = true;
      break;
    case PCAP_MAGIC_NANO_SWAPPED:
      swapped = true;
      isMicrosecond = false;
      break;
    default:
      throw new Error(`Unknown PCAP magic number: 0x${magicNumber.toString(16)}`);
  }

  return {
    magicNumber,
    versionMajor: view.getUint16(offset + 4, swapped),
    versionMinor: view.getUint16(offset + 6, swapped),
    thiszone: view.getInt32(offset + 8, swapped),
    sigfigs: view.getUint32(offset + 12, swapped),
    snaplen: view.getUint32(offset + 16, swapped),
    network: view.getUint32(offset + 20, swapped),
    isMicrosecond,
    swapped,
  };
}

/**
 * Parse a 16-byte PCAP packet header at the given offset.
 */
export function parsePcapPacketHeader(
  view: DataView,
  offset: number,
  swapped: boolean
): PcapPacketHeader {
  return {
    tsSec: view.getUint32(offset, swapped),
    tsFrac: view.getUint32(offset + 4, swapped),
    inclLen: view.getUint32(offset + 8, swapped),
    origLen: view.getUint32(offset + 12, swapped),
  };
}

/**
 * Parse an entire PCAP file from an ArrayBuffer.
 *
 * Never silently skips data: zero-length records are counted, a truncated final
 * record sets `truncated`, and an implausible record header stops parsing with
 * `stoppedEarly` describing why (record framing can't be trusted after that).
 */
export function parsePcap(buffer: ArrayBuffer): PcapParseResult {
  if (buffer.byteLength < GLOBAL_HEADER_SIZE) {
    throw new Error("File too small to be a PCAP file");
  }

  const view = new DataView(buffer);
  const globalHeader = parsePcapGlobalHeader(view, 0);
  const { swapped, snaplen } = globalHeader;
  // Upper bits of the network field carry FCS/flags in newer libpcap versions.
  const linkType = globalHeader.network & 0x0fffffff;
  const maxRecord = snaplen > 0 ? Math.min(Math.max(snaplen, 65535), MAX_PACKET_BYTES) : MAX_PACKET_BYTES;

  const packets: PcapRecord[] = [];
  let emptyRecords = 0;
  let truncated = false;
  let stoppedEarly: string | null = null;
  let offset = GLOBAL_HEADER_SIZE;

  while (offset < buffer.byteLength) {
    if (offset + PACKET_HEADER_SIZE > buffer.byteLength) {
      truncated = true;
      break;
    }

    const header = parsePcapPacketHeader(view, offset, swapped);
    offset += PACKET_HEADER_SIZE;
    const inclLen = header.inclLen;

    if (inclLen > maxRecord) {
      stoppedEarly =
        `Record ${packets.length + emptyRecords + 1} claims ${inclLen} captured bytes ` +
        `(snaplen ${snaplen}); the file is corrupt after this point.`;
      break;
    }

    if (offset + inclLen > buffer.byteLength) {
      truncated = true;
      break;
    }

    if (inclLen === 0) {
      emptyRecords++;
      continue;
    }

    packets.push({ header, data: buffer.slice(offset, offset + inclLen) });
    offset += inclLen;
  }

  return { globalHeader, linkType, packets, emptyRecords, truncated, stoppedEarly };
}

/**
 * Convert a PCAP packet header timestamp to microseconds since epoch.
 */
export function pcapTimestampToUs(header: PcapPacketHeader, isMicrosecond: boolean): number {
  const secInUs = header.tsSec * 1_000_000;
  const frac = isMicrosecond ? header.tsFrac : Math.floor(header.tsFrac / 1000);
  return secInUs + frac;
}
