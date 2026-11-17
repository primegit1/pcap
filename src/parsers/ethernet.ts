import type { EthernetFrame } from "../types/packets";

/** Ethernet frame header size without VLAN tagging */
const ETHERNET_HEADER_SIZE = 14;
/** VLAN tag (802.1Q) EtherType */
const ETHERTYPE_8021Q = 0x8100;
/** Q-in-Q (802.1ad) */
const ETHERTYPE_8021AD = 0x88a8;

/**
 * An Ethernet frame plus the payload bytes, used only while a packet is being
 * decoded. The payload copy is NOT retained on the decoded Packet (the raw frame
 * already holds the same bytes), which saves one full copy of every packet.
 */
export interface ParsedEthernetFrame extends EthernetFrame {
  payload: ArrayBuffer;
}

/**
 * Format a MAC address from 6 bytes.
 */
export function formatMac(bytes: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push(bytes[offset + i].toString(16).padStart(2, "0"));
  }
  return parts.join(":");
}

/**
 * Parse an Ethernet frame from raw packet data.
 * Handles VLAN tagging (802.1Q) by skipping the 4-byte VLAN tag.
 * Returns null if the data is too short.
 */
export function parseEthernet(data: ArrayBuffer): ParsedEthernetFrame | null {
  if (data.byteLength < ETHERNET_HEADER_SIZE) {
    return null;
  }

  const view = new DataView(data);
  const dstMacBytes = new Uint8Array(data, 0, 6);
  const srcMacBytes = new Uint8Array(data, 6, 6);

  const dstMac = formatMac(dstMacBytes, 0);
  const srcMac = formatMac(srcMacBytes, 0);

  let etherType = view.getUint16(12, false);
  let payloadOffset = ETHERNET_HEADER_SIZE;

  // Skip VLAN tags
  while (etherType === ETHERTYPE_8021Q || etherType === ETHERTYPE_8021AD) {
    if (data.byteLength < payloadOffset + 4) break;
    etherType = view.getUint16(payloadOffset + 2, false);
    payloadOffset += 4;
  }

  return {
    dstMac,
    srcMac,
    etherType,
    payload: data.slice(payloadOffset),
    payloadOffset,
  };
}
