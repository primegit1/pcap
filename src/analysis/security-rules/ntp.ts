import type { Packet, NTPHeader } from "../../types/packets";
import { Protocol } from "../../types/packets";

/**
 * NTP Mode values (RFC 5905) - used for packet identification
 */
const NTP_MODE_SERVER = 4;
const NTP_MODE_BROADCAST = 5;

/**
 * Stratum 255 = Kiss-of-death
 */
const NTP_STRATUM_KISS_OBR = 255;

// Import types from analysis module
import type { NTPServerInfo, NTPConversation, NTPAnalysisResult } from "../../types/analysis";

/**
 * Parse an NTP header from a UDP payload.
 * Returns null if the payload is too small or malformed.
 */
export function parseNTPHeader(payload: ArrayBuffer | null): NTPHeader | null {
  if (!payload || payload.byteLength < 4) {
    return null;
  }

  try {
    const view = new Uint8Array(payload);

    // First byte: LI (bits 7-6), Version (bits 5-3), Mode (bits 2-0)
    const firstByte = view[0];
    const leapIndicator = (firstByte >> 6) & 0x03;
    const version = (firstByte >> 3) & 0x07;
    const mode = firstByte & 0x07;

    // Second byte: Stratum
    const stratum = view[1];

    // Third byte: Poll interval
    const poll = view[2];

    // Fourth byte: Precision (signed)
    const precision = view[3];

    // Bytes 4-7: Root Delay (signed 32-bit, 16.16 fixed point)
    const rootDelay = ((view[4] << 24) | (view[5] << 16) | (view[6] << 8) | view[7]) / 65536;

    // Bytes 8-11: Root Dispersion (unsigned 32-bit, 16.16 fixed point)
    const rootDispersion = ((view[8] << 24) | (view[9] << 16) | (view[10] << 8) | view[11]) / 65536;

    // Bytes 12-15: Reference ID
    let referenceId = "";
    if (payload.byteLength >= 16) {
      // For stratum 1, it's 4 ASCII characters
      if (stratum === 1) {
        const chars = String.fromCharCode(view[12], view[13], view[14], view[15]);
        // Filter to printable ASCII
        referenceId = chars.replace(/[^\x20-\x7E]/g, "");
        if (!referenceId) {
          referenceId = `0x${view.slice(12, 16).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "")}`;
        }
      } else if (stratum === NTP_STRATUM_KISS_OBR) {
        // Kiss-o'-death code
        const kode = String.fromCharCode(view[12], view[13], view[14], view[15]).replace(/[^\x20-\x7E]/g, "");
        referenceId = `KoD:${kode || "unknown"}`;
      } else {
        // For stratum 2-15, it's an IPv4 address
        referenceId = `${view[12]}.${view[13]}.${view[14]}.${view[15]}`;
      }
    } else if (stratum >= 2 && stratum <= 15) {
      referenceId = "unknown";
    }

    // For the full 16-byte header + timestamps, we need up to 48 bytes minimum
    // We'll parse timestamps if available
    let referenceTimestamp: number | undefined;
    let originateTimestamp: number | undefined;
    let receiveTimestamp: number | undefined;
    let transmitTimestamp: number | undefined;

    // Only parse timestamps if we have enough data (timestamp = 8 bytes each, 4 timestamps = 32 bytes)
    if (payload.byteLength >= 48) {
      const data = new DataView(payload);
      // Reference timestamp (seconds since 1900)
      referenceTimestamp = data.getBigUint64(16, false) ? Number(data.getBigUint64(16, false)) : undefined;
      // Originate timestamp
      originateTimestamp = data.getBigUint64(24, false) ? Number(data.getBigUint64(24, false)) : undefined;
      // Receive timestamp
      receiveTimestamp = data.getBigUint64(32, false) ? Number(data.getBigUint64(32, false)) : undefined;
      // Transmit timestamp
      transmitTimestamp = data.getBigUint64(40, false) ? Number(data.getBigUint64(40, false)) : undefined;
    }

    return {
      leapIndicator,
      version,
      mode,
      stratum,
      poll,
      precision,
      rootDelay,
      rootDispersion,
      referenceId,
      referenceTimestamp,
      originateTimestamp,
      receiveTimestamp,
      transmitTimestamp,
    };
  } catch {
    // Return null on any parsing error for malformed packets
    return null;
  }
}

/**
 * Get the name of an NTP mode
 */
function getNTPModeName(mode: number): string {
  const modes: Record<number, string> = {
    1: "Symmetric Active",
    2: "Symmetric Passive",
    3: "Client",
    4: "Server",
    5: "Broadcast",
    6: "Control",
    7: "Private",
  };
  return modes[mode] || `Unknown(${mode})`;
}

/**
 * Get a descriptive summary of an NTP packet
 */
export function summarizeNTPNTPHeader(header: NTPHeader): string {
  const mode = getNTPModeName(header.mode);
  const leapNames: Record<number, string> = {
    0: "No warning",
    1: "Last minute has 61 seconds",
    2: "Last minute has 59 seconds",
    3: "Alarm (clock not synchronized)",
  };

  const parts: string[] = [`NTP v${header.version}`, mode];

  // Add leap indicator
  if (header.leapIndicator !== 0) {
    parts.push(leapNames[header.leapIndicator] || `LI=${header.leapIndicator}`);
  }

  // Add stratum info
  if (header.stratum === 0) {
    parts.push("unsynchronized");
  } else if (header.stratum === NTP_STRATUM_KISS_OBR) {
    parts.push(`Kiss-of-Death: ${header.referenceId}`);
  } else if (header.stratum >= 1 && header.stratum <= 15) {
    parts.push(`stratum=${header.stratum}`);
    if (header.referenceId) {
      parts.push(`ref=${header.referenceId}`);
    }
  }

  // Add poll interval
  if (header.poll > 0 && header.poll < 128) {
    const pollSec = Math.pow(2, header.poll);
    parts.push(`poll=${pollSec}s`);
  }

  return parts.join(" ");
}

/**
 * Analyze NTP packets to identify clients and servers.
 * Uses Mode field and request/response correlation to distinguish them.
 */
export function analyzeNTPTraffic(packets: Packet[]): NTPAnalysisResult {
  const ntpPackets = packets.filter(p =>
    p.protocol === Protocol.NTP &&
    p.ip &&
    p.transport &&
    "srcPort" in p.transport
  );

  const ntpConversations = new Map<string, {
    clientIp: string;
    clientPort: number;
    serverIp: string;
    serverPort: number;
    requestCount: number;
    responseCount: number;
    firstSeen: number;
    lastSeen: number;
    requestTimestamps: number[];
    responseTimestamps: number[];
  }>();

  const clients: NTPServerInfo[] = [];
  const confirmedServers: NTPServerInfo[] = [];
  const seenServers = new Map<string, NTPServerInfo>();

  for (const pkt of ntpPackets) {
    if (!pkt.ip || !pkt.transport || !pkt.appPayload) continue;

    const udp = pkt.transport as { srcPort: number; dstPort: number };
    const srcIp = pkt.ip.srcIp;
    const dstIp = pkt.ip.dstIp;
    const srcPort = udp.srcPort;
    const dstPort = udp.dstPort;

    const header = parseNTPHeader(pkt.appPayload);
    if (!header) continue;

    // Build conversation key (same flow in both directions)
    const convKey = `${srcIp}:${srcPort}-${dstIp}:${dstPort}`;
    const reverseKey = `${dstIp}:${dstPort}-${srcIp}:${srcPort}`;

    const existing = ntpConversations.get(convKey) || ntpConversations.get(reverseKey);

    const timestamp = pkt.timestampUs;

    let conversation;
    if (existing) {
      conversation = existing;
    } else {
      conversation = {
        clientIp: srcPort === 123 ? dstIp : srcIp,
        clientPort: srcPort === 123 ? dstPort : srcPort,
        serverIp: srcPort === 123 ? srcIp : dstIp,
        serverPort: 123,
        requestCount: 0,
        responseCount: 0,
        firstSeen: timestamp,
        lastSeen: timestamp,
        requestTimestamps: [],
        responseTimestamps: [],
      };
      ntpConversations.set(convKey, conversation);
    }

    conversation.lastSeen = timestamp;

    // Determine if this is a request or response based on port and mode
    // Primary indicator: source port
    if (srcPort === 123) {
      // From server (port 123) - typically response
      conversation.responseCount++;
      if (header.mode === NTP_MODE_SERVER || header.mode === NTP_MODE_BROADCAST) {
        conversation.responseTimestamps.push(timestamp);

        // Record the server info if not already seen
        if (!seenServers.has(dstIp)) {
          const serverInfo: NTPServerInfo = {
            ip: dstIp,
            port: dstPort,
            version: header.version,
            stratum: header.stratum,
            referenceId: header.referenceId,
            rootDelay: header.rootDelay,
            rootDispersion: header.rootDispersion,
            leapIndicator: header.leapIndicator,
            poll: header.poll,
            isServer: true,
            confidence: "high",
          };
          seenServers.set(dstIp, serverInfo);
          confirmedServers.push(serverInfo);
        }
      }
    } else if (dstPort === 123) {
      // To server (port 123) - definitely a request
      conversation.requestCount++;
      conversation.requestTimestamps.push(timestamp);

      // Record the client info
      const clientKey = srcIp;
      const existingClient = clients.find(c => c.ip === clientKey);
      if (!existingClient) {
        const clientInfo: NTPServerInfo = {
          ip: srcIp,
          port: srcPort,
          version: header.version,
          stratum: header.stratum,
          referenceId: header.referenceId,
          rootDelay: header.rootDelay,
          rootDispersion: header.rootDispersion,
          leapIndicator: header.leapIndicator,
          poll: header.poll,
          isServer: false,
          confidence: "medium",
        };
        clients.push(clientInfo);
      }
    }
  }

  // Now build conversation summaries with confidence
  const conversations: NTPConversation[] = Array.from(ntpConversations.values()).map(conv => {
    let confidence: "high" | "medium" | "low" = "low";
    if (conv.requestCount > 0 && conv.responseCount > 0) {
      // Check for request/response pairs based on timing (responses typically come after requests)
      const hasPairs = conv.requestTimestamps.some(reqTs =>
        conv.responseTimestamps.some(respTs => respTs > reqTs)
      );
      confidence = hasPairs ? "high" : "medium";
    } else if (conv.requestCount > 0 || conv.responseCount > 0) {
      confidence = "low";
    }

    return {
      clientIp: conv.clientIp,
      clientPort: conv.clientPort,
      serverIp: conv.serverIp,
      serverPort: conv.serverPort,
      requestCount: conv.requestCount,
      responseCount: conv.responseCount,
      firstSeen: conv.firstSeen,
      lastSeen: conv.lastSeen,
      confidence,
    };
  });

  // Update client confidence based on responses
  for (const conv of conversations) {
    if (conv.requestCount > 0 && conv.responseCount > 0) {
      const clientInfo = clients.find(c => c.ip === conv.clientIp);
      if (clientInfo) {
        clientInfo.confidence = "high";
      }
    }
  }

  return {
    clients,
    servers: confirmedServers,
    conversations,
  };
}