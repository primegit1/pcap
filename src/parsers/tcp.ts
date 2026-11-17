import type { TCPHeader, TCPOption } from "../types/packets";

const TCP_HEADER_MIN_SIZE = 20;

/**
 * Parse a TCP header from the given data at the given offset.
 * Returns null if data is too short.
 */
export function parseTCP(
  data: ArrayBuffer,
  offset: number = 0
): TCPHeader | null {
  const remaining = data.byteLength - offset;
  if (remaining < TCP_HEADER_MIN_SIZE) {
    return null;
  }

  const view = new DataView(data);

  const srcPort = view.getUint16(offset, false);
  const dstPort = view.getUint16(offset + 2, false);
  const sequenceNumber = view.getUint32(offset + 4, false);
  const acknowledgmentNumber = view.getUint32(offset + 8, false);
  const dataOffset = (view.getUint8(offset + 12) >> 4) * 4;

  if (dataOffset < TCP_HEADER_MIN_SIZE || dataOffset > remaining) {
    return null;
  }

  const flagsByte13 = view.getUint8(offset + 13);

  const fin = !!(flagsByte13 & 0x01);
  const syn = !!(flagsByte13 & 0x02);
  const rst = !!(flagsByte13 & 0x04);
  const psh = !!(flagsByte13 & 0x08);
  const ack = !!(flagsByte13 & 0x10);
  const urg = !!(flagsByte13 & 0x20);

  const window = view.getUint16(offset + 14, false);
  const checksum = view.getUint16(offset + 16, false);
  const urgentPointer = view.getUint16(offset + 18, false);

  // Parse options
  const options: TCPOption[] = [];
  let optOffset = offset + TCP_HEADER_MIN_SIZE;
  const optEnd = offset + dataOffset;

  while (optOffset + 2 <= optEnd) {
    const kind = view.getUint8(optOffset);
    if (kind === 0) {
      // End of options list (padding)
      break;
    }
    if (kind === 1) {
      // No-op
      options.push({ kind: 1 });
      optOffset += 1;
      continue;
    }

    const len = view.getUint8(optOffset + 1);
    if (len < 2 || optOffset + len > optEnd) break;

    // Copy the option bytes so the decoded header does not keep (or, on a worker
    // postMessage, drag along) the entire packet buffer alive.
    const optData = new Uint8Array(data, view.byteOffset + optOffset + 2, len - 2).slice();
    options.push({ kind, length: len, data: optData });
    optOffset += len;
  }

  return {
    srcPort,
    dstPort,
    sequenceNumber,
    acknowledgmentNumber,
    dataOffset,
    fin,
    syn,
    rst,
    psh,
    ack,
    urg,
    window,
    checksum,
    urgentPointer,
    options,
    payloadOffset: offset + dataOffset,
    payloadLength: remaining - dataOffset,
  };
}

/**
 * Get a human-readable string for TCP flags.
 */
export function formatTCPFlags(flags: {
  fin: boolean;
  syn: boolean;
  rst: boolean;
  psh: boolean;
  ack: boolean;
  urg: boolean;
}): string {
  const chars: string[] = [];
  if (flags.syn) chars.push("SYN");
  if (flags.ack) chars.push("ACK");
  if (flags.fin) chars.push("FIN");
  if (flags.rst) chars.push("RST");
  if (flags.psh) chars.push("PSH");
  if (flags.urg) chars.push("URG");
  return chars.length > 0 ? chars.join(" ") : "-";
}
