import type { IPv6Header } from "../types/packets";

const IPV6_HEADER_SIZE = 40;

/** Extension header type codes */
const EXT_HOP_BY_HOP = 0;
const EXT_ROUTING = 43;
const EXT_FRAGMENT = 44;
const EXT_DESTINATION = 60;
const EXT_MOBILITY = 135;
const EXT_HOST_IDENTITY = 139;
const EXT_SHIM6 = 140;

/** Set of extension header numbers to skip over */
const EXTENSION_HEADERS = new Set([
  EXT_HOP_BY_HOP,
  EXT_ROUTING,
  EXT_FRAGMENT,
  EXT_DESTINATION,
  EXT_MOBILITY,
  EXT_HOST_IDENTITY,
  EXT_SHIM6,
]);

/**
 * Parse an IPv6 header from raw data at the given offset.
 * Skips extension headers to find the actual payload.
 * Returns null if data is too short or version is wrong.
 */
export function parseIPv6(
  data: ArrayBuffer,
  offset: number = 0
): IPv6Header | null {
  const remaining = data.byteLength - offset;
  if (remaining < IPV6_HEADER_SIZE) {
    return null;
  }

  const view = new DataView(data);

  // First 4 bytes: version (4 bits) + traffic class (8 bits) + flow label (20 bits)
  const firstWord = view.getUint32(offset, false);
  const version = firstWord >>> 28;
  if (version !== 6) return null;

  const trafficClass = (firstWord >>> 20) & 0xff;
  const flowLabel = firstWord & 0x0fffff;

  const payloadLength = view.getUint16(offset + 4, false);
  const nextHeader = view.getUint8(offset + 6);
  const hopLimit = view.getUint8(offset + 7);

  const srcIp = formatIPv6(view, offset + 8);
  const dstIp = formatIPv6(view, offset + 24);

  // Skip extension headers
  let currentOffset = offset + IPV6_HEADER_SIZE;
  let currentNextHeader = nextHeader;
  let remainingPayload = payloadLength;

  while (EXTENSION_HEADERS.has(currentNextHeader)) {
    if (currentOffset + 2 > data.byteLength) break;

    const extHdrLen = view.getUint8(currentOffset + 1);
    const extTotalLen = (extHdrLen + 1) * 8;

    if (currentNextHeader === EXT_FRAGMENT) {
      // Fragment header is fixed 8 bytes
      currentNextHeader = view.getUint8(currentOffset);
      currentOffset += 8;
      remainingPayload -= 8;
      break; // Any headers after fragment are in the second fragment
    }

    currentNextHeader = view.getUint8(currentOffset);
    currentOffset += extTotalLen;
    remainingPayload -= extTotalLen;
  }

  return {
    version: 6,
    trafficClass,
    flowLabel,
    payloadLength: remainingPayload,
    nextHeader: currentNextHeader,
    protocol: currentNextHeader,
    hopLimit,
    srcIp,
    dstIp,
    payloadOffset: currentOffset,
    payloadLen: remainingPayload,
  };
}

/**
 * Format an IPv6 address from 16 bytes at the given offset.
 * Uses the standard hex colon notation with zero compression.
 */
export function formatIPv6(view: DataView, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    const val = view.getUint16(offset + i * 2, false);
    parts.push(val.toString(16));
  }

  // Zero compression: replace longest run of zeros with "::"
  let longestStart = -1;
  let longestLen = 0;
  let currentStart = -1;
  let currentLen = 0;

  for (let i = 0; i < 8; i++) {
    if (parts[i] === "0") {
      if (currentStart === -1) {
        currentStart = i;
        currentLen = 1;
      } else {
        currentLen++;
      }
      if (currentLen > longestLen) {
        longestStart = currentStart;
        longestLen = currentLen;
      }
    } else {
      currentStart = -1;
      currentLen = 0;
    }
  }

  if (longestLen < 2) {
    return parts.join(":");
  }

  const before = parts.slice(0, longestStart).join(":");
  const after = parts.slice(longestStart + longestLen).join(":");
  return `${before}::${after}`;
}
