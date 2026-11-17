import type { IPv4Header } from "../types/packets";

const IPV4_HEADER_MIN_SIZE = 20;

/**
 * Parse an IPv4 header from raw data.
 * Returns null if data is too short or version is wrong.
 */
export function parseIPv4(data: ArrayBuffer, offset: number = 0): IPv4Header | null {
  const remaining = data.byteLength - offset;
  if (remaining < IPV4_HEADER_MIN_SIZE) {
    return null;
  }

  const view = new DataView(data);
  const byte0 = view.getUint8(offset);
  const version = byte0 >> 4;
  if (version !== 4) return null;

  const ihl = byte0 & 0x0f;
  const headerLength = ihl * 4;

  if (remaining < headerLength) {
    return null;
  }

  const byte1 = view.getUint8(offset + 1);

  return {
    version: 4,
    ihl,
    dscp: byte1 >> 2,
    ecn: byte1 & 0x03,
    totalLength: view.getUint16(offset + 2, false),
    identification: view.getUint16(offset + 4, false),
    flags: view.getUint8(offset + 6) >> 5,
    fragmentOffset: view.getUint16(offset + 6, false) & 0x1fff,
    ttl: view.getUint8(offset + 8),
    protocol: view.getUint8(offset + 9),
    headerChecksum: view.getUint16(offset + 10, false),
    srcIp: formatIPv4(view, offset + 12),
    dstIp: formatIPv4(view, offset + 16),
    payloadOffset: offset + headerLength,
    payloadLen: remaining - headerLength,
  };
}

/**
 * Format an IPv4 address from 4 bytes at the given offset.
 */
export function formatIPv4(view: DataView, offset: number): string {
  return `${view.getUint8(offset)}.${view.getUint8(offset + 1)}.${view.getUint8(offset + 2)}.${view.getUint8(offset + 3)}`;
}
