import type { IGMPHeader } from "../types/packets";

/**
 * IGMP message types (RFC 3375)
 */
const IGMP_TYPE = {
  QUERY: 0x11,          // 17 - IGMPv2 Query, IGMPv3 Query
  V2_REPORT: 0x12,      // 18 - IGMPv2 Membership Report
  V3_REPORT: 0x16,      // 22 - IGMPv3 Membership Report
  V1_REPORT: 0x12,      // 18 - IGMPv1/v2 Membership Report (same as V2)
  LEAVE: 0x17,          // 23 - IGMPv2 Leave Group
};

/**
 * Minimum IGMP header size (IGMPv2)
 */
const IGMP_MIN_HEADER_SIZE = 8;

/**
 * Parse an IGMP header from raw packet data.
 * Supports IGMPv1, IGMPv2, and IGMPv3.
 * Returns null if data is too short.
 */
export function parseIGMP(data: ArrayBuffer, offset: number = 0): IGMPHeader | null {
  const remaining = data.byteLength - offset;
  if (remaining < IGMP_MIN_HEADER_SIZE) {
    return null;
  }

  const view = new DataView(data);
  const type = view.getUint8(offset);

  // Determine version based on type field
  // IGMPv1/v2: type 0x12 (18) for reports, 0x11 (17) for query
  // IGMPv3: type 0x16 (22) for reports, also 0x11 for query
  let version: number;
  if (type === IGMP_TYPE.V3_REPORT) {
    version = 3;
  } else if (type === IGMP_TYPE.V2_REPORT) {
    version = 2;
  } else {
    version = 1;
  }

  const maxResponseTime = view.getUint8(offset + 1);
  const checksum = view.getUint16(offset + 2, false);

  const result: IGMPHeader = {
    version,
    type,
    maxResponseTime,
    checksum,
  };

  // For queries (type 17), extract group address (or 0.0.0.0 for all-groups)
  if (type === IGMP_TYPE.QUERY) {
    const groupAddrBytes = new Uint8Array(data, offset + 4, 4);
    const groupIp = formatIP(groupAddrBytes);
    // 0.0.0.0 means query for all groups
    if (groupIp !== "0.0.0.0") {
      result.groupAddress = groupIp;
    }
    // For IGMPv3 queries, there's additional data (aux data, source list)
    // We'll handle this simply for now
  }

  // For reports (v2 or v3)
  if (type === IGMP_TYPE.V2_REPORT || type === IGMP_TYPE.V1_REPORT) {
    const groupAddrBytes = new Uint8Array(data, offset + 4, 4);
    result.groupAddress = formatIP(groupAddrBytes);
  }

  // For IGMPv3 reports, parse the detailed header
  if (version === 3 && type === IGMP_TYPE.V3_REPORT) {
    // IGMPv3 Report structure:
    // 1-16: IGMP header (8 bytes)
    // 17-18: Number of group records (2 bytes)
    // Then for each group:
    //   1: Type (include/exclude)
    //   2-3: Number of sources (2 bytes)
    //   4-7: Group address (4 bytes)
    //   Then source addresses (4 bytes each)

    if (remaining >= 12) {
      const numGroups = view.getUint16(offset + 8, false);
      let pos = offset + 12;

      const groupAddresses: string[] = [];
      const sourceAddresses: string[] = [];

      for (let i = 0; i < numGroups && pos + 8 <= data.byteLength; i++) {
        void view.getUint8(pos); // groupType (1=include, 2=exclude) - currently unused
        const numSources = view.getUint16(pos + 1, false);
        const groupBytes = new Uint8Array(data, pos + 4, 4);
        const groupAddr = formatIP(groupBytes);

        if (groupAddr && groupAddr !== "0.0.0.0") {
          groupAddresses.push(groupAddr);
        }

        // Parse source addresses
        for (let j = 0; j < numSources && pos + 8 + j * 4 + 4 <= data.byteLength; j++) {
          const srcBytes = new Uint8Array(data, pos + 8 + j * 4, 4);
          sourceAddresses.push(formatIP(srcBytes));
        }

        pos += 8 + numSources * 4;
      }

      if (groupAddresses.length > 0) {
        result.groupAddress = groupAddresses.join(", ");
      }
      if (sourceAddresses.length > 0) {
        result.sourceAddresses = [...new Set(sourceAddresses)];
      }
    }
  }

  return result;
}

/**
 * Format 4 bytes as an IP address string.
 */
function formatIP(bytes: Uint8Array): string {
  if (bytes.length < 4) return "0.0.0.0";
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

/**
 * Get a human-readable description for an IGMP type.
 */
export function getIGMPTypeDescription(type: number, version: number): string {
  if (version === 3) {
    const typeMap: Record<number, string> = {
      17: "Query",
      22: "Membership Report",
      23: "Leave Group",
    };
    return typeMap[type] ?? `Type ${type}`;
  }

  const typeMap: Record<number, string> = {
    [IGMP_TYPE.QUERY]: "Query",
    [IGMP_TYPE.V2_REPORT]: "Membership Report",
    [IGMP_TYPE.V1_REPORT]: "Membership Report",
    [IGMP_TYPE.LEAVE]: "Leave Group",
  };
  return typeMap[type] ?? `Type ${type}`;
}

/**
 * Get the IGMP message type name for display.
 */
export function getIGMPTypeName(type: number): string {
  const typeMap: Record<number, string> = {
    [IGMP_TYPE.QUERY]: "Query",
    [IGMP_TYPE.V2_REPORT]: "Report",
    [IGMP_TYPE.V3_REPORT]: "Report (v3)",
    [IGMP_TYPE.LEAVE]: "Leave",
  };
  return typeMap[type] ?? `Type ${type}`;
}