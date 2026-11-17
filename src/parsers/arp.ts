/**
 * ARP (Address Resolution Protocol) parser.
 * RFC 826 — maps IPv4 addresses to MAC addresses on Ethernet.
 *
 * ARP frame structure for Ethernet/IPv4:
 *   Hardware type (2), Protocol type (2),
 *   HW addr length (1), Proto addr length (1),
 *   Operation (2),
 *   Sender MAC (6), Sender IP (4),
 *   Target MAC (6), Target IP (4)
 *   = 28 bytes total
 */

/** Parsed ARP packet */
export interface ARPHeader {
  /** Hardware type: 1 = Ethernet */
  hwType: number;
  /** Protocol type: 0x0800 = IPv4 */
  protoType: number;
  /** Hardware address length (typically 6 for MAC) */
  hwAddrLen: number;
  /** Protocol address length (typically 4 for IPv4) */
  protoAddrLen: number;
  /** Operation: 1 = Request, 2 = Reply */
  operation: number;
  /** Sender hardware address (MAC) */
  senderMac: string;
  /** Sender protocol address (IP) */
  senderIp: string;
  /** Target hardware address (MAC) — all zeros in requests */
  targetMac: string;
  /** Target protocol address (IP) */
  targetIp: string;
}

/** Known ARP operation codes */
export const ARP_OPERATION: Record<number, string> = {
  1: "Request",
  2: "Reply",
  3: "RARP Request",
  4: "RARP Reply",
};

/**
 * Parse an ARP frame from raw data.
 * Returns null if the data is too short or not Ethernet/IPv4 ARP.
 */
export function parseARP(data: ArrayBuffer, offset: number = 0): ARPHeader | null {
  const remaining = data.byteLength - offset;
  // Minimum ARP frame: 8-byte fixed header
  if (remaining < 8) return null;

  const view = new DataView(data);

  const hwType = view.getUint16(offset, false);
  const protoType = view.getUint16(offset + 2, false);
  const hwAddrLen = view.getUint8(offset + 4);
  const protoAddrLen = view.getUint8(offset + 5);
  const operation = view.getUint16(offset + 6, false);

  // Sanity check: Ethernet IPv4 ARP
  if (hwType !== 1 && protoType !== 0x0800) {
    // Allow non-Ethernet/non-IPv4 ARP — parse what we can
  }

  const totalLen = 8 + hwAddrLen * 2 + protoAddrLen * 2;
  if (remaining < totalLen) return null;

  const bytes = new Uint8Array(data, offset + 8, totalLen - 8);

  // Sender MAC
  let pos = 0;
  const senderMacBytes: string[] = [];
  for (let i = 0; i < hwAddrLen; i++) {
    senderMacBytes.push(bytes[pos + i].toString(16).padStart(2, "0"));
  }
  const senderMac = senderMacBytes.join(":");
  pos += hwAddrLen;

  // Sender IP
  const senderIpBytes: string[] = [];
  for (let i = 0; i < protoAddrLen; i++) {
    senderIpBytes.push(String(bytes[pos + i]));
  }
  const senderIp = senderIpBytes.join(".");
  pos += protoAddrLen;

  // Target MAC
  const targetMacBytes: string[] = [];
  for (let i = 0; i < hwAddrLen; i++) {
    targetMacBytes.push(bytes[pos + i].toString(16).padStart(2, "0"));
  }
  const targetMac = targetMacBytes.join(":");
  pos += hwAddrLen;

  // Target IP
  const targetIpBytes: string[] = [];
  for (let i = 0; i < protoAddrLen; i++) {
    targetIpBytes.push(String(bytes[pos + i]));
  }
  const targetIp = targetIpBytes.join(".");

  return {
    hwType,
    protoType,
    hwAddrLen,
    protoAddrLen,
    operation,
    senderMac,
    senderIp,
    targetMac,
    targetIp,
  };
}

/**
 * Get a human-readable name for an ARP operation code.
 */
export function getARPOperationName(operation: number): string {
  return ARP_OPERATION[operation] ?? `Op ${operation}`;
}

/**
 * Produce a human-readable summary of an ARP packet.
 */
export function summarizeARP(payload: ArrayBuffer): string {
  const arp = parseARP(payload);
  if (!arp) return "ARP";

  const opName = getARPOperationName(arp.operation);

  if (arp.operation === 1) {
    // Request
    const isGratuitous = arp.senderIp === arp.targetIp;
    if (isGratuitous) {
      return `ARP Gratuitous Request: ${arp.senderIp} is at ${arp.senderMac}`;
    }
    const isProbe = arp.senderIp === "0.0.0.0";
    if (isProbe) {
      return `ARP Probe: Who has ${arp.targetIp}? (${arp.senderMac})`;
    }
    return `ARP Request: Who has ${arp.targetIp}? Tell ${arp.senderIp}`;
  }

  if (arp.operation === 2) {
    // Reply
    const isGratuitous = arp.senderIp === arp.targetIp;
    if (isGratuitous) {
      return `ARP Gratuitous Reply: ${arp.senderIp} is at ${arp.senderMac}`;
    }
    return `ARP Reply: ${arp.senderIp} is at ${arp.senderMac}`;
  }

  return `ARP ${opName}: ${arp.senderIp} (${arp.senderMac}) ↔ ${arp.targetIp} (${arp.targetMac})`;
}
