/**
 * Link-layer normalization.
 *
 * The decoder (parsePacket) understands Ethernet frames. Captures taken on other
 * link types are converted by stripping the capture's own link header and
 * prepending a synthetic 14-byte Ethernet header (zero MACs unless the source
 * carries one), so every layer above sees the same structure.
 */

export const LINKTYPE = {
  NULL: 0,
  ETHERNET: 1,
  RAW: 101,
  LOOP: 108,
  LINUX_SLL: 113,
  IPV4: 228,
  IPV6: 229,
  LINUX_SLL2: 276,
} as const;

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;

const SUPPORTED = new Set<number>(Object.values(LINKTYPE));

export function isSupportedLinkType(linkType: number): boolean {
  return SUPPORTED.has(linkType);
}

/** Human-readable names for the link types people commonly hit. */
export function linkTypeName(linkType: number): string {
  switch (linkType) {
    case 0: return "BSD loopback (NULL)";
    case 1: return "Ethernet";
    case 101: return "Raw IP";
    case 105: return "IEEE 802.11 Wi-Fi";
    case 108: return "OpenBSD loopback";
    case 113: return "Linux cooked (SLL)";
    case 127: return "IEEE 802.11 + radiotap";
    case 228: return "Raw IPv4";
    case 229: return "Raw IPv6";
    case 276: return "Linux cooked v2 (SLL2)";
    default: return `link type ${linkType}`;
  }
}

function wrapInEthernet(
  data: ArrayBuffer,
  l3Offset: number,
  etherType: number,
  srcMac?: Uint8Array
): ArrayBuffer | null {
  const l3Len = data.byteLength - l3Offset;
  if (l3Len <= 0) return null;
  const out = new Uint8Array(14 + l3Len);
  if (srcMac && srcMac.length === 6) out.set(srcMac, 6);
  out[12] = etherType >> 8;
  out[13] = etherType & 0xff;
  out.set(new Uint8Array(data, l3Offset, l3Len), 14);
  return out.buffer;
}

function etherTypeFromIpVersion(data: ArrayBuffer, offset: number): number | null {
  if (data.byteLength <= offset) return null;
  const version = new Uint8Array(data, offset, 1)[0] >> 4;
  if (version === 4) return ETHERTYPE_IPV4;
  if (version === 6) return ETHERTYPE_IPV6;
  return null;
}

/**
 * Convert one captured frame to an Ethernet-framed buffer.
 * Returns the input untouched for Ethernet, or null if the frame can't be converted.
 */
export function normalizeFrame(data: ArrayBuffer, linkType: number): ArrayBuffer | null {
  switch (linkType) {
    case LINKTYPE.ETHERNET:
      return data;

    case LINKTYPE.RAW:
    case LINKTYPE.IPV4:
    case LINKTYPE.IPV6: {
      const et = etherTypeFromIpVersion(data, 0);
      return et === null ? null : wrapInEthernet(data, 0, et);
    }

    case LINKTYPE.NULL:
    case LINKTYPE.LOOP: {
      // 4-byte address family (byte order and values differ per OS), then the IP packet.
      const et = etherTypeFromIpVersion(data, 4);
      return et === null ? null : wrapInEthernet(data, 4, et);
    }

    case LINKTYPE.LINUX_SLL: {
      if (data.byteLength < 17) return null;
      const view = new DataView(data);
      const addrLen = view.getUint16(4, false);
      const proto = view.getUint16(14, false);
      const mac = addrLen === 6 ? new Uint8Array(data, 6, 6) : undefined;
      return wrapInEthernet(data, 16, proto, mac);
    }

    case LINKTYPE.LINUX_SLL2: {
      if (data.byteLength < 21) return null;
      const view = new DataView(data);
      const proto = view.getUint16(0, false);
      const addrLen = view.getUint8(11);
      const mac = addrLen === 6 ? new Uint8Array(data, 12, 6) : undefined;
      return wrapInEthernet(data, 20, proto, mac);
    }

    default:
      return null;
  }
}
