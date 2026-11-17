import type {
  PcapngSectionHeaderBlock,
  PcapngInterfaceDescriptionBlock,
  PcapngPacket,
} from "../types/packets";

/* ========== Block Type Codes ========== */
const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_EPB = 0x00000006;
const BLOCK_SPB = 0x00000003;

/** Value of the SHB byte-order magic when read in the file's own byte order. */
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

const OPTION_ENDOFOPT = 0;
const OPTION_IF_TSRESOL = 9;

const DEFAULT_TS_RESOLUTION = 1_000_000;

export interface PcapngParseResult {
  sections: PcapngSectionHeaderBlock[];
  /** Interfaces of every section, in file order */
  interfaces: PcapngInterfaceDescriptionBlock[];
  packets: PcapngPacket[];
  /** True when the file ended in the middle of a block */
  truncated: boolean;
}

export function isPcapngMagic(firstWordBigEndian: number): boolean {
  return firstWordBigEndian === BLOCK_SHB;
}

/**
 * Read TLV-style options. Options are padded to 4-byte alignment.
 */
function parseOptions(
  view: DataView,
  offset: number,
  endOffset: number,
  le: boolean
): Map<number, Uint8Array> {
  const options = new Map<number, Uint8Array>();

  while (offset + 4 <= endOffset) {
    const code = view.getUint16(offset, le);
    const len = view.getUint16(offset + 2, le);
    offset += 4;

    if (code === OPTION_ENDOFOPT) break;
    if (offset + len > endOffset) break;

    if (len > 0) {
      options.set(code, new Uint8Array(view.buffer, view.byteOffset + offset, len));
    }

    offset += len + ((4 - (len % 4)) % 4);
  }

  return options;
}

function parseSHB(
  view: DataView,
  offset: number,
  blockLength: number,
  le: boolean
): PcapngSectionHeaderBlock {
  // Section length is a signed 64-bit value (-1 = unspecified).
  const lo = view.getUint32(offset + 16 + (le ? 0 : 4), le);
  const hi = view.getInt32(offset + 16 + (le ? 4 : 0), le);
  return {
    blockType: BLOCK_SHB,
    blockLength,
    byteOrderMagic: view.getUint32(offset + 8, le),
    majorVersion: view.getUint16(offset + 12, le),
    minorVersion: view.getUint16(offset + 14, le),
    sectionLength: hi * 2 ** 32 + lo,
    options: parseOptions(view, offset + 24, offset + blockLength - 4, le),
  };
}

/** Decode the if_tsresol option byte into ticks per second. */
function resolutionFromOption(byte: number): number {
  const exponent = byte & 0x7f;
  const base = byte & 0x80 ? 2 : 10;
  const resolution = Math.pow(base, exponent);
  return Number.isFinite(resolution) && resolution >= 1 ? resolution : DEFAULT_TS_RESOLUTION;
}

/**
 * Interface Description Block layout: type(4) len(4) linktype(2) reserved(2)
 * snaplen(4) options... — so options begin at +16.
 */
function parseIDB(
  view: DataView,
  offset: number,
  blockLength: number,
  le: boolean
): PcapngInterfaceDescriptionBlock {
  const options = parseOptions(view, offset + 16, offset + blockLength - 4, le);
  const tsresol = options.get(OPTION_IF_TSRESOL);

  return {
    blockType: BLOCK_IDB,
    blockLength,
    linkType: view.getUint16(offset + 8, le),
    reserved: view.getUint16(offset + 10, le),
    snapLen: view.getUint32(offset + 12, le),
    options,
    timestampResolution:
      tsresol && tsresol.length >= 1 ? resolutionFromOption(tsresol[0]) : DEFAULT_TS_RESOLUTION,
  };
}

/** Convert a tick count (given as hi/lo 32-bit words) to microseconds without losing precision. */
export function ticksToMicroseconds(timestamp: bigint, resolution: number): number {
  if (!Number.isSafeInteger(resolution) || resolution < 1) {
    return Math.floor(Number(timestamp) / (resolution / 1_000_000));
  }
  return Number((timestamp * 1_000_000n) / BigInt(resolution));
}

/**
 * Parse an entire PCAPNG file from an ArrayBuffer.
 *
 * Honors the byte order declared in each Section Header Block (little- and
 * big-endian files are both common), tracks interfaces per section, and throws
 * a descriptive Error on structural corruption. A truncated final block is
 * tolerated and reported via `truncated`.
 */
export function parsePcapng(buffer: ArrayBuffer): PcapngParseResult {
  const view = new DataView(buffer);
  const sections: PcapngSectionHeaderBlock[] = [];
  const allInterfaces: PcapngInterfaceDescriptionBlock[] = [];
  const packets: PcapngPacket[] = [];

  let sectionInterfaces: PcapngInterfaceDescriptionBlock[] = [];
  let le = true;
  let haveSection = false;
  let truncated = false;
  let offset = 0;

  while (offset + 8 <= buffer.byteLength) {
    // The SHB type is a palindrome, so it can be recognized before the byte order is known.
    const isSHB = view.getUint32(offset, false) === BLOCK_SHB;

    if (isSHB) {
      if (offset + 12 > buffer.byteLength) {
        truncated = true;
        break;
      }
      const magicBE = view.getUint32(offset + 8, false);
      if (magicBE === BYTE_ORDER_MAGIC) le = false;
      else if (view.getUint32(offset + 8, true) === BYTE_ORDER_MAGIC) le = true;
      else {
        throw new Error(
          `Invalid pcapng byte-order magic 0x${magicBE.toString(16)} at offset ${offset}`
        );
      }
    } else if (!haveSection) {
      throw new Error("Not a valid pcapng file: the first block is not a Section Header Block");
    }

    const blockType = isSHB ? BLOCK_SHB : view.getUint32(offset, le);
    const blockLength = view.getUint32(offset + 4, le);

    if (blockLength < 12 || blockLength % 4 !== 0) {
      throw new Error(
        `Malformed pcapng block at offset ${offset}: invalid length ${blockLength} (must be >= 12 and a multiple of 4)`
      );
    }
    if (offset + blockLength > buffer.byteLength) {
      truncated = true;
      break;
    }
    const trailingLength = view.getUint32(offset + blockLength - 4, le);
    if (trailingLength !== blockLength) {
      throw new Error(
        `Malformed pcapng block at offset ${offset}: leading length ${blockLength} != trailing length ${trailingLength}`
      );
    }

    switch (blockType) {
      case BLOCK_SHB:
        haveSection = true;
        sections.push(parseSHB(view, offset, blockLength, le));
        sectionInterfaces = []; // interface IDs restart in every section
        break;

      case BLOCK_IDB: {
        const idb = parseIDB(view, offset, blockLength, le);
        sectionInterfaces.push(idb);
        allInterfaces.push(idb);
        break;
      }

      case BLOCK_EPB: {
        if (blockLength < 32) break;
        const interfaceId = view.getUint32(offset + 8, le);
        const tsHigh = view.getUint32(offset + 12, le);
        const tsLow = view.getUint32(offset + 16, le);
        const timestamp = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
        const capturedPacketLength = view.getUint32(offset + 20, le);
        const originalPacketLength = view.getUint32(offset + 24, le);

        const dataStart = offset + 28;
        const available = Math.max(0, offset + blockLength - 4 - dataStart);
        const capLen = Math.min(capturedPacketLength, available);
        const iface = sectionInterfaces[interfaceId];
        const resolution = iface?.timestampResolution ?? DEFAULT_TS_RESOLUTION;

        const paddedLen = capLen + ((4 - (capLen % 4)) % 4);
        packets.push({
          blockType: BLOCK_EPB,
          blockLength,
          interfaceId,
          timestamp,
          capturedPacketLength: capLen,
          originalPacketLength,
          packetData: buffer.slice(dataStart, dataStart + capLen),
          options: parseOptions(view, dataStart + paddedLen, offset + blockLength - 4, le),
          linkType: iface?.linkType ?? 1,
          timestampResolution: resolution,
          timestampUs: ticksToMicroseconds(timestamp, resolution),
        });
        break;
      }

      case BLOCK_SPB: {
        // Simple Packet Block: original length, then data. No timestamp is available.
        if (blockLength < 16) break;
        const originalLength = view.getUint32(offset + 8, le);
        const available = blockLength - 16;
        const capLen = Math.min(originalLength, available);
        const iface = sectionInterfaces[0];
        packets.push({
          blockType: BLOCK_SPB,
          blockLength,
          interfaceId: 0,
          timestamp: 0n,
          capturedPacketLength: capLen,
          originalPacketLength: originalLength,
          packetData: buffer.slice(offset + 12, offset + 12 + capLen),
          options: new Map(),
          linkType: iface?.linkType ?? 1,
          timestampResolution: iface?.timestampResolution ?? DEFAULT_TS_RESOLUTION,
          timestampUs: 0,
        });
        break;
      }

      default:
        // Name resolution, statistics, custom blocks, ... are not needed.
        break;
    }

    offset += blockLength;
  }

  return { sections, interfaces: allInterfaces, packets, truncated };
}

/**
 * Convert a PCAPNG packet timestamp to microseconds since epoch.
 * (Kept for API compatibility; `PcapngPacket.timestampUs` is already populated.)
 */
export function pcapngTimestampToUs(
  epb: { timestamp: bigint },
  resolution: number
): number {
  return ticksToMicroseconds(epb.timestamp, resolution);
}
