

/**
 * Parse TLS ClientHello/ServerHello.
 */
export function summarizeTLS(payload: ArrayBuffer): string {
  if (payload.byteLength < 3) return "";
  const view = new Uint8Array(payload);

  // TLS record header: content_type(1) + version(2) + length(2)
  const contentType = view[0];
  // TLS plaintext content types
  const contentTypes: Record<number, string> = {
    20: "Change Cipher Spec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat",
  };
  const typeName = contentTypes[contentType] ?? `Type 0x${contentType.toString(16)}`;

  if (payload.byteLength < 5) return typeName;

  // TLS version (major.minor)
  const majorVer = view[1];
  const minorVer = view[2];
  const verStr = `${majorVer}.${minorVer}`;

  // Check for handshake messages
  if (contentType === 22 && payload.byteLength >= 6) {
    const handshakeType = view[5];
    const hsMap: Record<number, string> = {
      1:  "ClientHello",
      2:  "ServerHello",
      3:  "NewSessionTicket",
      4:  "HelloRetryRequest",
      11: "Certificate",
      12: "ServerKeyExchange",
      13: "CertificateRequest",
      14: "ServerHelloDone",
      15: "CertificateVerify",
      16: "ClientKeyExchange",
      20: "Finished",
      22: "CertificateStatus",
      23: "KeyUpdate",
    };
    const hsName = hsMap[handshakeType] ?? `HS type=${handshakeType}`;

    // For ClientHello (handshake type 1), try to extract SNI
    if (handshakeType === 1 && payload.byteLength >= 50) {
      // Try to find SNI extension: type 0x0000 at offset ~ 48+
      const sni = extractSNI(view);
      return sni ? `TLS ${verStr} ${hsName} SNI=${sni}` : `TLS ${verStr} ${hsName}`;
    }

    return `TLS ${verStr} ${hsName}`;
  }

  // Alert messages
  if (contentType === 21 && payload.byteLength >= 7) {
    const alertLevel = view[5]; // 1=warning, 2=fatal
    const alertDesc = view[6];
    const alerts: Record<number, string> = {
      0: "Close Notify",
      10: "Unexpected Message",
      20: "Bad MAC",
      21: "Decryption Failed",
      22: "Record Overflow",
      30: "Decompression Failure",
      40: "Handshake Failure",
      41: "No Certificate",
      42: "Bad Certificate",
      43: "Unsupported Certificate",
      44: "Certificate Revoked",
      45: "Certificate Expired",
      46: "Certificate Unknown",
      47: "Illegal Parameter",
      48: "Unknown CA",
      49: "Access Denied",
      50: "Decode Error",
      51: "Decrypt Error",
      60: "Export Restriction",
      70: "Protocol Version",
      71: "Insufficient Security",
      72: "Internal Error",
      80: "Inappropriate Fallback",
      90: "User Canceled",
      100: "No Renegotiation",
      110: "Missing Extension",
      111: "Unsupported Extension",
      112: "Certificate Unobtainable",
      113: "Unrecognized Name",
      114: "Bad Certificate Status Response",
      115: "Bad Certificate Hash Value",
      116: "Unknown PSK Identity",
    };
    const levelStr = alertLevel === 2 ? "Fatal" : "Warning";
    const alertStr = alerts[alertDesc] ?? `Alert ${alertDesc}`;
    return `${typeName} [${levelStr}] ${alertStr}`;
  }

  return `${typeName} (TLS ${verStr})`;
}


/**
 * Try to extract SNI from a TLS ClientHello payload.
 */
export function extractSNI(view: Uint8Array): string | null {
  // Very rough heuristic: after handshake header (4 bytes for type+length)
  // find the extensions block at variable offset
  // We look for the SNI extension type 0x0000 followed by length
  for (let i = 50; i < Math.min(view.length - 9, 250); i++) {
    if (view[i] === 0x00 && view[i + 1] === 0x00) {
      // Possible SNI extension
      const extLen = (view[i + 2] << 8) | view[i + 3];
      if (extLen > 0 && extLen < 256 && i + 4 + extLen <= view.length) {
        if (i + 6 + 3 <= view.length && view[i + 6] === 0x00) {
          // Server name type 0 = host_name
          const nameLen = (view[i + 7] << 8) | view[i + 8];
          if (nameLen > 0 && nameLen < 200 && i + 9 + nameLen <= view.length) {
            const nameBytes = view.slice(i + 9, i + 9 + nameLen);
            return String.fromCharCode(...nameBytes);
          }
        }
      }
    }
  }
  return null;
}


/**
 * Summarize IPSec/IKE (Internet Key Exchange) payload.
 * IKE uses UDP 500/4500. Main message types:
 * IKEv1: Phase 1 (Main/Aggressive) and Phase 2 (Quick Mode)
 * IKEv2: SA_INIT, SA_AUTH, CREATE_CHILD_SA, INFORMATIONAL, IKE_SESSION_RESUME
 */
export function summarizeIPSecIKE(payload: ArrayBuffer): string {
  if (payload.byteLength < 28) return "IKE";
  const view = new Uint8Array(payload);

  // IKE header: initiator SPI (8) + responder SPI (8) + next payload (1) + version (1) + exchange type (1) + flags (1) + message ID (4) + length (4)
  const version = view[17]; // IKE version: 0x10=IKEv1, 0x20=IKEv2
  const exchangeType = view[19];

  if (version >= 0x20) {
    const ikev2Exchanges: Record<number, string> = {
      34: "IKE_SA_INIT",
      35: "IKE_SA_AUTH",
      36: "CREATE_CHILD_SA",
      37: "INFORMATIONAL",
      38: "IKE_SESSION_RESUME",
    };
    const exName = ikev2Exchanges[exchangeType] ?? `Exchange ${exchangeType}`;
    return `IKEv2 ${exName}`;
  } else {
    const ikev1Exchanges: Record<number, string> = {
      2: "Identity Protection (Main Mode)",
      4: "Aggressive Mode",
      6: "Quick Mode",
      5: "Informational",
    };
    const exName = ikev1Exchanges[exchangeType] ?? `Exchange ${exchangeType}`;
    const flags = view[20];
    const isInitiator = (flags & 0x08) !== 0;
    return `IKEv1 ${exName}${isInitiator ? " (Initiator)" : ""}`;
  }
}


/**
 * Summarize OpenVPN payload.
 * OpenVPN has its own framing. Packet format:
 * - P_CONTROL_HARD_RESET_CLIENT_V2 (1), P_CONTROL_HARD_RESET_SERVER_V2 (2)
 * - P_CONTROL_V1 (4), P_ACK_V1 (5), P_DATA_V1 (6)
 * - P_CONTROL_HARD_RESET_CLIENT_V3 (7), P_CONTROL_HARD_RESET_SERVER_V3 (8)
 */
export function summarizeOpenVPN(payload: ArrayBuffer): string {
  if (payload.byteLength < 1) return "OpenVPN";
  const view = new Uint8Array(payload);
  const opcode = view[0] >> 3;
  const keyId = view[0] & 0x07;

  const opcodeNames: Record<number, string> = {
    1: "CONTROL_HARD_RESET_CLIENT_V2",
    2: "CONTROL_HARD_RESET_SERVER_V2",
    3: "CONTROL_SOFT_RESET_V1",
    4: "CONTROL_V1",
    5: "ACK_V1",
    6: "DATA_V1",
    7: "CONTROL_HARD_RESET_CLIENT_V3",
    8: "CONTROL_HARD_RESET_SERVER_V3",
    9: "DATA_V2",
    10: "CONTROL_WKC_V1",
  };

  const opName = opcodeNames[opcode] ?? `Opcode ${opcode}`;

  if (opcode === 6 || opcode === 9) {
    return `OpenVPN DATA (key ${keyId})`;
  }

  if (opcode === 5) {
    return "OpenVPN ACK";
  }

  if (opcode === 1 || opcode === 7) {
    return "OpenVPN Handshake Init (Client)";
  }

  if (opcode === 2 || opcode === 8) {
    return "OpenVPN Handshake Response (Server)";
  }

  return `OpenVPN ${opName}`;
}


/**
 * Summarize QUIC payload.
 * QUIC packets start with flags byte. Short header (1 byte flags + connection ID).
 * Long header: 1 byte flags + 4 byte version + DCID len + DCID + SCID len + SCID + ...
 * Flag byte bit 7 (0x80) = long header, bit 6 (0x40) = fixed bit (must be 1).
 */
export function summarizeQUIC(payload: ArrayBuffer): string {
  if (payload.byteLength < 1) return "QUIC";
  const view = new Uint8Array(payload);

  const firstByte = view[0];
  const isLongHeader = (firstByte & 0x80) !== 0;

  if (isLongHeader && payload.byteLength >= 6) {
    // Long header: extract version
    const version = (view[1] << 24) | (view[2] << 16) | (view[3] << 8) | view[4];

    const versionNames: Record<number, string> = {
      0x00000001: "v1 (RFC 9000)",
      0x6b3343cf: "v2 (RFC 9369)",
      0xff000020: "draft-32",
      0xff00001d: "draft-29",
      0x51303530: "Version Negotiation",
      0x00000000: "Version Negotiation",
    };

    const verName = versionNames[version] ?? `0x${version.toString(16)}`;

    // Extract form type from low bits of first byte
    const formType = (firstByte >> 4) & 0x03;
    const longTypes: Record<number, string> = {
      0: "Initial",
      1: "0-RTT",
      2: "Handshake",
      3: "Retry",
    };

    const packetType = longTypes[formType] ?? "Unknown";
    return `QUIC ${packetType} ${verName}`;
  }

  // Short header: just 1-RTT protected data
  return "QUIC 1-RTT (Short Header)";
}


/**
 * Summarize WireGuard traffic.
 * WireGuard uses a simple binary header: 1-byte message type + 3-byte reserved + body.
 * Message types: 1=Handshake Initiation, 2=Handshake Response, 3=Cookie Reply, 4=Transport Data
 */
export function summarizeWireGuard(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "WireGuard";
  const view = new Uint8Array(payload);
  const msgType = view[0];

  const typeNames: Record<number, string> = {
    1: "Handshake Initiation",
    2: "Handshake Response",
    3: "Cookie Reply",
    4: "Transport Data",
  };

  const typeName = typeNames[msgType] ?? `Unknown (0x${msgType.toString(16)})`;

  if (msgType === 4 && payload.byteLength >= 8) {
    // Transport Data: 4-byte header + 4-byte counter + encrypted payload
    const counter = view[4] | (view[5] << 8) | (view[6] << 16) | (view[7] << 24);
    return `WireGuard ${typeName} #${counter >>> 0}`;
  }

  return `WireGuard ${typeName}`;
}
