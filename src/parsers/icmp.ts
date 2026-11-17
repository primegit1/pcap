import type { ICMPHeader } from "../types/packets";

const ICMP_HEADER_SIZE = 8;

/**
 * ICMP type descriptions (common types).
 */
export const ICMP_TYPE_DESCRIPTIONS: Record<number, string> = {
  // ICMPv4
  0: "Echo Reply",
  3: "Destination Unreachable",
  4: "Source Quench",
  5: "Redirect",
  8: "Echo Request",
  9: "Router Advertisement",
  10: "Router Solicitation",
  11: "Time Exceeded",
  12: "Parameter Problem",
  13: "Timestamp Request",
  14: "Timestamp Reply",
  15: "Information Request",
  16: "Information Reply",
  17: "Address Mask Request",
  18: "Address Mask Reply",
};

/**
 * ICMPv6 type descriptions.
 */
export const ICMPV6_TYPE_DESCRIPTIONS: Record<number, string> = {
  1: "Destination Unreachable",
  2: "Packet Too Big",
  3: "Time Exceeded",
  4: "Parameter Problem",
  128: "Echo Request",
  129: "Echo Reply",
  130: "Multicast Listener Query",
  131: "Multicast Listener Report",
  132: "Multicast Listener Done",
  133: "Router Solicitation",
  134: "Router Advertisement",
  135: "Neighbor Solicitation",
  136: "Neighbor Advertisement",
};

/**
 * Parse an ICMP header (v4 or v6) from the given data at the given offset.
 * Use `isV6=true` for ICMPv6.
 * Returns null if data is too short.
 */
export function parseICMP(
  data: ArrayBuffer,
  offset: number = 0,
  isV6: boolean = false
): ICMPHeader | null {
  const remaining = data.byteLength - offset;
  if (remaining < ICMP_HEADER_SIZE) {
    return null;
  }

  const view = new DataView(data);

  return {
    type: view.getUint8(offset),
    code: view.getUint8(offset + 1),
    checksum: view.getUint16(offset + 2, false),
    isV6,
    payloadOffset: offset + ICMP_HEADER_SIZE,
    payloadLength: remaining - ICMP_HEADER_SIZE,
  };
}

/**
 * Get a human-readable description for an ICMP type.
 */
export function getICMPTypeDescription(type: number, isV6: boolean): string {
  const descriptions = isV6 ? ICMPV6_TYPE_DESCRIPTIONS : ICMP_TYPE_DESCRIPTIONS;
  return descriptions[type] ?? `Type ${type}`;
}
