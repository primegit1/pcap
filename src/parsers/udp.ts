import type { UDPHeader } from "../types/packets";

const UDP_HEADER_SIZE = 8;

/**
 * Parse a UDP header from the given data at the given offset.
 * Returns null if data is too short.
 */
export function parseUDP(
  data: ArrayBuffer,
  offset: number = 0
): UDPHeader | null {
  const remaining = data.byteLength - offset;
  if (remaining < UDP_HEADER_SIZE) {
    return null;
  }

  const view = new DataView(data);

  const srcPort = view.getUint16(offset, false);
  const dstPort = view.getUint16(offset + 2, false);
  const length = view.getUint16(offset + 4, false);
  const checksum = view.getUint16(offset + 6, false);

  // UDP length includes the header itself
  const payloadLength = Math.max(0, length - UDP_HEADER_SIZE);

  return {
    srcPort,
    dstPort,
    length,
    checksum,
    payloadOffset: offset + UDP_HEADER_SIZE,
    payloadLength,
  };
}
