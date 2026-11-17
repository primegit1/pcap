import { Protocol } from "../../types/packets";
import { firstLineAsText } from "./shared";

/**
 * Summarize DHCP payload - detect message type.
 */
export function summarizeDHCP(payload: ArrayBuffer): string {
  if (payload.byteLength < 240) return "";
  const view = new Uint8Array(payload);

  // DHCP message type (option 53) is in the options area starting at byte 240
  // Basic structure: bootp header (236 bytes) + magic cookie (4) + options
  const magic = (view[236] << 24) | (view[237] << 16) | (view[238] << 8) | view[239];
  if (magic !== 0x63825363) return "";

  // Parse option 53 (DHCP Message Type)
  let pos = 240;
  while (pos + 1 < view.length) {
    const opt = view[pos];
    if (opt === 0xff) break; // End option
    if (opt === 0x00) { pos++; continue; } // Pad
    const len = view[pos + 1];
    if (pos + 2 + len > view.length) break;

    if (opt === 53 && len >= 1) {
      const msgType = view[pos + 2];
      const types: Record<number, string> = {
        1: "DISCOVER",
        2: "OFFER",
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NAK",
        7: "RELEASE",
        8: "INFORM",
      };
      const typeDesc = types[msgType] ?? `Type ${msgType}`;

      // Try to extract client IP from yiaddr (bytes 16-19) for OFFER/ACK
      if ((msgType === 2 || msgType === 5) && view.length >= 20) {
        const clientIp = `${view[16]}.${view[17]}.${view[18]}.${view[19]}`;
        if (clientIp !== "0.0.0.0") {
          return `DHCP ${typeDesc} → ${clientIp}`;
        }
      }

      // Try to extract requested IP from option 50
      let requestedIp = "";
      let pos2 = 240;
      while (pos2 + 1 < view.length && !requestedIp) {
        const o = view[pos2];
        if (o === 0xff) break;
        if (o === 0x00) { pos2++; continue; }
        const l = view[pos2 + 1];
        if (pos2 + 2 + l > view.length) break;
        if (o === 50 && l >= 4) {
          requestedIp = `${view[pos2 + 2]}.${view[pos2 + 3]}.${view[pos2 + 4]}.${view[pos2 + 5]}`;
        }
        pos2 += 2 + l;
      }

      if (requestedIp) return `DHCP ${typeDesc} (request ${requestedIp})`;
      return `DHCP ${typeDesc}`;
    }
    pos += 2 + len;
  }

  return "DHCP";
}


/**
 * Summarize NTP payload - parse mode, version, stratum.
 * Provides detailed information including mode, version, stratum, and reference ID.
 */
export function summarizeNTP(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "";
  const view = new Uint8Array(payload);
  const firstByte = view[0];

  const mode = firstByte & 0x07;
  const version = (firstByte >> 3) & 0x07;
  const leap = (firstByte >> 6) & 0x03;

  const modeNames: Record<number, string> = {
    0: "Reserved",
    1: "Symmetric Active",
    2: "Symmetric Passive",
    3: "Client",
    4: "Server",
    5: "Broadcast",
    6: "NTP Control",
    7: "Private (reserved)",
  };
  const leapNames: Record<number, string> = {
    0: "No Warning",
    1: "Last Minute 61 Sec",
    2: "Last Minute 59 Sec",
    3: "Alarm (Clock Not Sync)",
  };

  const modeName = modeNames[mode] ?? `Mode ${mode}`;

  // For Client/Server, check stratum
  if (payload.byteLength >= 4) {
    const stratum = view[1];

    // Get reference ID (bytes 12-15)
    let refIdStr = "";
    if (payload.byteLength >= 16) {
      const refIdBytes = view.slice(12, 16);

      if (stratum === 1) {
        // Stratum 1 = primary server, reference ID is 4 ASCII characters
        const chars = String.fromCharCode(refIdBytes[0], refIdBytes[1], refIdBytes[2], refIdBytes[3]);
        const cleaned = chars.replace(/[^\x20-\x7E]/g, "");
        refIdStr = cleaned || `0x${Array.from(refIdBytes).map(b => b.toString(16).padStart(2, "0")).join("")}`;
      } else if (stratum === 255) {
        // Kiss-of-death
        const kos = String.fromCharCode(refIdBytes[0], refIdBytes[1], refIdBytes[2], refIdBytes[3]).replace(/[^\x20-\x7E]/g, "");
        refIdStr = `Kiss-o'-death: ${kos || "unknown"}`;
      } else if (stratum >= 2 && stratum <= 15) {
        // Stratum 2-15 = IP address of source clock
        refIdStr = `${refIdBytes[0]}.${refIdBytes[1]}.${refIdBytes[2]}.${refIdBytes[3]}`;
      }
    }

    if (stratum === 0) {
      return `NTP v${version} ${modeName} ${leapNames[leap] ?? ""}`.trim();
    }
    if (refIdStr) {
      return `NTP v${version} ${modeName} stratum=${stratum} ref=${refIdStr}`;
    }
    if (stratum >= 1 && stratum <= 15) {
      return `NTP v${version} ${modeName} stratum=${stratum}`;
    }
  }

  const leapLabel = leap !== 0 ? ` [${leapNames[leap]}]` : "";
  return `NTP v${version} ${modeName}${leapLabel}`;
}


/**
 * Summarize SMB protocol - dialect and command.
 */
export function summarizeSMB(payload: ArrayBuffer): string {
  if (payload.byteLength < 8) return "";
  const view = new Uint8Array(payload);

  // SMBv1 header starts with 0xff 0x53 0x4d 0x42 ('\xffSMB')
  if (view[0] === 0xff && view[1] === 0x53 && view[2] === 0x4d && view[3] === 0x42) {
    const cmd = view[4];
    const cmdMap: Record<number, string> = {
      0x00: "SMB_COM_CREATE_DIRECTORY",
      0x01: "SMB_COM_DELETE_DIRECTORY",
      0x02: "SMB_COM_OPEN",
      0x03: "SMB_COM_CREATE",
      0x04: "SMB_COM_CLOSE",
      0x05: "SMB_COM_FLUSH",
      0x06: "SMB_COM_DELETE",
      0x07: "SMB_COM_RENAME",
      0x08: "SMB_COM_QUERY_INFORMATION",
      0x09: "SMB_COM_SET_INFORMATION",
      0x0a: "SMB_COM_READ",
      0x0b: "SMB_COM_WRITE",
      0x0c: "SMB_COM_LOCK_BYTE_RANGE",
      0x0d: "SMB_COM_UNLOCK_BYTE_RANGE",
      0x0e: "SMB_COM_CREATE_TEMPORARY",
      0x0f: "SMB_COM_CREATE_NEW",
      0x10: "SMB_COM_CHECK_DIRECTORY",
      0x11: "SMB_COM_PROCESS_EXIT",
      0x12: "SMB_COM_SEEK",
      0x13: "SMB_COM_LOCK_AND_READ",
      0x14: "SMB_COM_WRITE_AND_UNLOCK",
      0x17: "SMB_COM_READ_RAW",
      0x18: "SMB_COM_READ_MPX",
      0x19: "SMB_COM_READ_MPX_SECONDARY",
      0x1a: "SMB_COM_WRITE_RAW",
      0x1b: "SMB_COM_WRITE_MPX",
      0x1c: "SMB_COM_WRITE_COMPLETE",
      0x20: "SMB_COM_QUERY_SERVER",
      0x21: "SMB_COM_SET_INFORMATION2",
      0x22: "SMB_COM_QUERY_INFORMATION2",
      0x23: "SMB_COM_LOCKING_ANDX",
      0x24: "SMB_COM_TRANSACTION",
      0x25: "SMB_COM_TRANSACTION_SECONDARY",
      0x26: "SMB_COM_IOCTL",
      0x27: "SMB_COM_IOCTL_SECONDARY",
      0x28: "SMB_COM_COPY",
      0x29: "SMB_COM_MOVE",
      0x2a: "SMB_COM_ECHO",
      0x2b: "SMB_COM_WRITE_AND_CLOSE",
      0x2c: "SMB_COM_OPEN_ANDX",
      0x2d: "SMB_COM_READ_ANDX",
      0x2e: "SMB_COM_WRITE_ANDX",
      0x2f: "SMB_COM_CLOSE_AND_TREE_DISC",
      0x32: "SMB_COM_TRANSACTION2",
      0x33: "SMB_COM_TRANSACTION2_SECONDARY",
      0x34: "SMB_COM_FIND_CLOSE2",
      0x35: "SMB_COM_FIND_NOTIFY_CLOSE",
      0x70: "SMB_COM_TREE_CONNECT",
      0x71: "SMB_COM_TREE_DISCONNECT",
      0x72: "SMB_COM_NEGOTIATE",
      0x73: "SMB_COM_SESSION_SETUP_ANDX",
      0x74: "SMB_COM_LOGOFF_ANDX",
      0x75: "SMB_COM_TREE_CONNECT_ANDX",
      0xa0: "SMB_COM_NT_TRANSACT",
      0xa1: "SMB_COM_NT_TRANSACT_SECONDARY",
      0xa2: "SMB_COM_NT_CREATE_ANDX",
      0xe0: "SMB_COM_USER_SPECIAL",
    };
    const cmdName = cmdMap[cmd] ?? `SMB cmd=0x${cmd.toString(16)}`;
    return `SMBv1: ${cmdName}`;
  }

  // SMBv2 header starts with 0xfe 0x53 0x4d 0x42 ('\xfeSMB')
  if (view[0] === 0xfe && view[1] === 0x53 && view[2] === 0x4d && view[3] === 0x42 &&
      payload.byteLength >= 16) {
    const cmd = (view[12] << 8) | view[13];
    const v2CmdMap: Record<number, string> = {
      0x0000: "SMB2 NEGOTIATE",
      0x0001: "SMB2 SESSION_SETUP",
      0x0002: "SMB2 LOGOFF",
      0x0003: "SMB2 TREE_CONNECT",
      0x0004: "SMB2 TREE_DISCONNECT",
      0x0005: "SMB2 CREATE",
      0x0006: "SMB2 CLOSE",
      0x0007: "SMB2 FLUSH",
      0x0008: "SMB2 READ",
      0x0009: "SMB2 WRITE",
      0x000a: "SMB2 LOCK",
      0x000b: "SMB2 IOCTL",
      0x000c: "SMB2 CANCEL",
      0x000d: "SMB2 ECHO",
      0x000e: "SMB2 QUERY_DIRECTORY",
      0x000f: "SMB2 CHANGE_NOTIFY",
      0x0010: "SMB2 QUERY_INFO",
      0x0011: "SMB2 SET_INFO",
      0x0012: "SMB2 OPLOCK_BREAK",
    };
    const cmdName = v2CmdMap[cmd] ?? `SMB2 cmd=0x${cmd.toString(16)}`;
    return cmdName;
  }

  return "SMB";
}


/**
 * Parse BER TLV for SNMP.
 */
export function parseBER(buf: Uint8Array, offset: number): { tag: number; length: number; value: Uint8Array; consumed: number } | null {
  if (offset >= buf.length) return null;
  const tag = buf[offset];
  let pos = offset + 1;
  if (pos >= buf.length) return null;
  let len = buf[pos];
  pos++;
  if (len > 0x7f) {
    const numOctets = len & 0x7f;
    if (numOctets === 0 || numOctets > 4) return null;
    len = 0;
    for (let i = 0; i < numOctets; i++) {
      if (pos >= buf.length) return null;
      len = (len << 8) | buf[pos];
      pos++;
    }
  }
  if (pos + len > buf.length) return null;
  const value = buf.slice(pos, pos + len);
  return { tag, length: len, value, consumed: pos + len - offset };
}


/**
 * Summarize SNMP payload.
 */
export function summarizeSNMP(payload: ArrayBuffer): string {
  if (payload.byteLength < 6) return "";
  const view = new Uint8Array(payload);
  const seq = parseBER(view, 0);
  if (!seq || seq.tag !== 0x30) return "";

  const ver = parseBER(seq.value, 0);
  if (!ver || ver.tag !== 0x02) return "";
  const version = ver.value[0] ?? 0;

  let pos = ver.consumed;
  let community = "";
  if (version < 3) {
    const comm = parseBER(seq.value, pos);
    if (comm && comm.tag === 0x04) {
      community = String.fromCharCode(...comm.value);
      pos += comm.consumed;
    }
  }

  const pdu = parseBER(seq.value, pos);
  if (!pdu) return "";
  const pduTypes: Record<number, string> = {
    0xa0: "GetRequest",
    0xa1: "GetNextRequest",
    0xa2: "GetResponse",
    0xa3: "SetRequest",
    0xa5: "Trap",
    0xa8: "InformRequest",
    0xa9: "SNMPv2Trap",
    0xab: "GetBulkRequest",
  };
  const pduName = pduTypes[pdu.tag] ?? `PDU-0x${pdu.tag.toString(16)}`;

  const verLabel = version === 0 ? "v1" : version === 1 ? "v2c" : version === 3 ? "v3" : `v${version}`;
  if (community) {
    return `${pduName} ${verLabel} community="${community}"`;
  }
  return `${pduName} ${verLabel}`;
}


/**
 * Summarize Syslog - parse facility, severity, message.
 */
export function summarizeSyslog(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 300);
  if (!text) return "";

  // Syslog format: <PRI>version timestamp hostname app message
  const priMatch = text.match(/^<(\d{1,3})>/);
  if (priMatch) {
    const pri = parseInt(priMatch[1], 10);
    const facility = pri >> 3;
    const severity = pri & 0x07;

    const facilityNames: Record<number, string> = {
      0: "kern", 1: "user", 2: "mail", 3: "daemon",
      4: "auth", 5: "syslog", 6: "lpr", 7: "news",
      8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
      16: "local0", 17: "local1", 18: "local2", 19: "local3",
      20: "local4", 21: "local5", 22: "local6", 23: "local7",
    };
    const severityNames: Record<number, string> = {
      0: "emerg", 1: "alert", 2: "crit", 3: "error",
      4: "warning", 5: "notice", 6: "info", 7: "debug",
    };

    const facName = facilityNames[facility] ?? `facility=${facility}`;
    const sevName = severityNames[severity] ?? `sev=${severity}`;

    // Extract message body (after PRI, possibly after structured data)
    const rest = text.slice(priMatch[0].length).trim();
    const msgBody = rest.length > 60 ? rest.slice(0, 60) + "..." : rest;

    return `${facName}.${sevName}: ${msgBody}`;
  }

  return text.slice(0, 100);
}


/**
 * Summarize MDNS / DNS payload.
 */
export function summarizeDNS(payload: ArrayBuffer, _protocol: Protocol): string {
  if (payload.byteLength < 12) return "";
  const view = new Uint8Array(payload);
  const isResp = !!(view[2] & 0x80);
  const opcode = (view[2] >> 3) & 0x0f;
  const opcodeNames: Record<number, string> = {
    0: "QUERY",
    1: "IQUERY (Inverse)",
    2: "STATUS",
    4: "NOTIFY",
    5: "UPDATE",
  };
  const opName = opcodeNames[opcode] ?? `Op=${opcode}`;

  // Extract query name
  let pos = 12;
  const parts: string[] = [];
  while (pos < payload.byteLength) {
    const len = view[pos];
    if (len === 0) break;
    if (len >= 0xc0) {
      pos = 12; break;
    }
    const part = String.fromCharCode(...Array.from(view.slice(pos + 1, pos + 1 + len)));
    parts.push(part);
    pos += 1 + len;
  }
  const qname = parts.join(".");

  // Extract query type (QTYPE) at pos+1, pos+2
  let qtype = "";
  if (pos + 2 < payload.byteLength) {
    const qt = (view[pos + 1] << 8) | view[pos + 2];
    const typeNames: Record<number, string> = {
      1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
      15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 28: "AAAA",
      33: "SRV", 35: "NAPTR", 99: "SPF", 255: "ANY",
      257: "CAA", 32768: "ID",
    };
    qtype = typeNames[qt] ?? `TYPE=${qt}`;
  }

  const prefix = isResp ? "Response" : "Query";
  const dsc = `${prefix} ${opName}`;
  if (qname && qtype) return `${dsc}: ${qname} (${qtype})`;
  if (qname) return `${dsc}: ${qname}`;
  return dsc;
}


/**
 * Summarize LDAP payload.
 */
export function summarizeLDAP(payload: ArrayBuffer): string {
  if (payload.byteLength < 5) return "";
  const view = new Uint8Array(payload);
  if (view[0] === 0x30 && view.length > 2) {
    const innerStart = 2;
    if (innerStart < view.length) {
      const opTag = view[innerStart];
      const opMap: Record<number, string> = {
        0x60: "Bind Request",
        0x61: "Bind Response",
        0x42: "Unbind Request",
        0x63: "Search Request",
        0x64: "Search Result Entry",
        0x65: "Search Result Done",
        0x66: "Modify Request",
        0x67: "Modify Response",
        0x68: "Add Request",
        0x69: "Add Response",
        0x4a: "Delete Request",
        0x4b: "Delete Response",
        0x6c: "Modify DN Request",
        0x6d: "Modify DN Response",
        0x6e: "Compare Request",
        0x6f: "Compare Response",
        0x50: "Abandon Request",
        0x70: "Extended Request",
        0x71: "Extended Response",
      };
      const opName = opMap[opTag] ?? `LDAP Op 0x${opTag.toString(16)}`;
      if (opTag === 0x60) {
        const bindText = String.fromCharCode(...Array.from(view.slice(Math.min(10, view.length))));
        const clean = bindText.replace(/[^\x20-\x7e]/g, "").trim();
        return clean ? `${opName}: ${clean}` : opName;
      }
      return opName;
    }
  }
  const text = firstLineAsText(payload, 100);
  return text || "";
}


/**
 * Summarize IGMP payload.
 */
export function summarizeIGMP(payload: ArrayBuffer): string {
  // IGMP header is 8 bytes minimum
  if (payload.byteLength < 8) return "IGMP";

  const view = new Uint8Array(payload);
  const type = view[0];
  const typeNames: Record<number, string> = {
    17: "Query",
    18: "Report",
    22: "Report (v3)",
    23: "Leave",
  };
  const typeName = typeNames[type] ?? `Type ${type}`;

  // Extract group address for reports/queries
  let detail = "";
  if (type === 17) {
    // Query - group address might be 0.0.0.0 (all groups) or specific group
    const g1 = view[4];
    const g2 = view[5];
    const g3 = view[6];
    const g4 = view[7];
    const groupIp = `${g1}.${g2}.${g3}.${g4}`;
    if (groupIp !== "0.0.0.0") {
      detail = `group=${groupIp}`;
    }
  } else if (type === 18 || type === 22 || type === 23) {
    // Report or Leave - group address
    const g1 = view[4];
    const g2 = view[5];
    const g3 = view[6];
    const g4 = view[7];
    const groupIp = `${g1}.${g2}.${g3}.${g4}`;
    detail = `group=${groupIp}`;
    // For IGMPv3 reports, check for source addresses
    if (type === 22 && payload.byteLength >= 12) {
      const numGroups = ((view[8] << 8) | view[9]);
      if (numGroups > 0 && payload.byteLength >= 12 + numGroups * 8) {
        const sources: string[] = [];
        for (let i = 0; i < numGroups; i++) {
          const numSources = ((view[12 + i * 8 + 1] << 8) | view[12 + i * 8 + 2]);
          for (let j = 0; j < numSources; j++) {
            const s1 = view[12 + i * 8 + 6 + j * 4];
            const s2 = view[12 + i * 8 + 7 + j * 4];
            const s3 = view[12 + i * 8 + 8 + j * 4];
            const s4 = view[12 + i * 8 + 9 + j * 4];
            sources.push(`${s1}.${s2}.${s3}.${s4}`);
          }
        }
        if (sources.length > 0) {
          detail += `, sources=${sources.slice(0, 3).join(", ")}${sources.length > 3 ? `...+${sources.length-3}` : ""}`;
        }
      }
    }
  }

  return detail ? `${typeName} (${detail})` : typeName;
}


/**
 * Summarize BGP (Border Gateway Protocol) payload.
 * BGP messages: 16-byte marker + 2-byte length + 1-byte type.
 * Types: 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE, 5=ROUTE-REFRESH
 */
export function summarizeBGP(payload: ArrayBuffer): string {
  if (payload.byteLength < 19) return "BGP";
  const view = new Uint8Array(payload);

  // Verify marker (16 bytes of 0xFF for BGP)
  let isBGP = true;
  for (let i = 0; i < 16; i++) {
    if (view[i] !== 0xff) { isBGP = false; break; }
  }
  if (!isBGP) return "BGP (invalid marker)";

  const msgLen = (view[16] << 8) | view[17];
  const msgType = view[18];

  const typeNames: Record<number, string> = {
    1: "OPEN",
    2: "UPDATE",
    3: "NOTIFICATION",
    4: "KEEPALIVE",
    5: "ROUTE-REFRESH",
  };

  const typeName = typeNames[msgType] ?? `Unknown (${msgType})`;

  if (msgType === 1 && payload.byteLength >= 29) {
    // OPEN: version, my AS, hold time, identifier
    const version = view[19];
    const myAS = (view[20] << 8) | view[21];
    const holdTime = (view[22] << 8) | view[23];
    const bgpId = `${view[24]}.${view[25]}.${view[26]}.${view[27]}`;
    return `BGP OPEN v${version} AS${myAS} ID ${bgpId} Hold ${holdTime}s`;
  }

  if (msgType === 2) {
    // UPDATE — contains withdrawn routes and/or announcements
    return `BGP UPDATE (len ${msgLen})`;
  }

  if (msgType === 3 && payload.byteLength >= 21) {
    // NOTIFICATION: error code + subcode
    const errCode = view[19];
    const errSub = view[20];
    return `BGP NOTIFICATION Error ${errCode}/${errSub}`;
  }

  return `BGP ${typeName}`;
}


/**
 * Summarize Kerberos payload.
 * Kerberos messages are ASN.1 DER encoded. Application tags:
 * 10=AS-REQ, 11=AS-REP, 12=TGS-REQ, 13=TGS-REP, 14=AP-REQ, 15=AP-REP, 20=KRB-ERROR
 */
export function summarizeKerberos(payload: ArrayBuffer): string {
  if (payload.byteLength < 2) return "Kerberos";
  const view = new Uint8Array(payload);

  // ASN.1: first byte = application tag, second = length
  const tag = view[0];

  // Application tags: high bits 01 + tag number in low 5 bits
  const appTag = tag & 0x1f;

  const tagNames: Record<number, string> = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    15: "AP-REP",
    20: "KRB-ERROR",
    30: "KRB-SAFE",
    31: "KRB-PRIV",
  };

  const typeName = tagNames[appTag];
  if (typeName) {
    if (appTag === 20 && payload.byteLength >= 6) {
      // KRB-ERROR: error code at offset after ASN.1 header
      return `Kerberos ${typeName}`;
    }
    return `Kerberos ${typeName}`;
  }

  return "Kerberos";
}


/**
 * Summarize NetBIOS payload.
 * NetBIOS Name Service (UDP 137): DNS-like format with names.
 * NetBIOS Datagram Service (UDP 138): messages between hosts.
 * NetBIOS Session Service (TCP 139): SMB-like session.
 */
export function summarizeNetBIOS(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "NetBIOS";
  const view = new Uint8Array(payload);

  // NetBIOS Name Service (port 137) — similar to DNS
  // Header: TX ID (2) + flags (2) + questions/answers
  const flags = (view[2] << 8) | view[3];
  const isResponse = (flags & 0x8000) !== 0;

  if (isResponse) {
    const answerCount = (view[6] << 8) | view[7];
    return `NetBIOS Name Service Response (answers: ${answerCount})`;
  }

  const qdCount = (view[4] << 8) | view[5];
  if (qdCount > 0) {
    // Try to extract NetBIOS name from query (encoded as 32 bytes of A-Z + scope)
    if (payload.byteLength > 18) {
      let name = "";
      for (let i = 12; i < Math.min(44, view.length); i++) {
        const ch = view[i];
        if (ch >= 0x41 && ch <= 0x5a) name += String.fromCharCode(ch - 0x41 + 'A'.charCodeAt(0));
        else if (ch === 0x00) break;
      }
      if (name.length > 1) {
        // NetBIOS names are padded to 15 chars with spaces, strip trailing spaces
        name = name.trimEnd();
        return `NetBIOS Name Query: ${name}`;
      }
    }
    return `NetBIOS Name Query`;
  }

  return "NetBIOS";
}


/**
 * Summarize DHCPv6 payload.
 */
export function summarizeDHCPv6Payload(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "DHCPv6";

  const view = new Uint8Array(payload);
  const msgType = view[0];

  // DHCPv6 message type names
  const typeNames: Record<number, string> = {
    1: "Solicit",
    2: "Advertise",
    3: "Request",
    4: "Reply",
    5: "Relay-Forward",
    6: "Relay-Reply",
    7: "ACK",
    8: "NAK",
    9: "Decline",
    10: "Reconfigure",
    11: "Information-Request",
  };
  const typeName = typeNames[msgType] ?? `Type ${msgType}`;

  // Transaction ID (bytes 1-3)
  const txId = (
    (view[1] << 16) |
    (view[2] << 8) |
    view[3]
  ).toString(16).padStart(6, '0');

  return `${typeName} TXID=${txId}`;
}


/**
 * Summarize STUN messages — decode message type from first 2 bytes.
 */
export function summarizeSTUN(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "STUN packet";
  const view = new Uint8Array(payload);
  const msgType = (view[0] << 8) | view[1];
  const typeMap: Record<number, string> = {
    0x0001: "Binding Request",
    0x0101: "Binding Success Response",
    0x0111: "Binding Error Response",
    0x0003: "Allocate Request",
    0x0103: "Allocate Success",
    0x0004: "Refresh Request",
    0x0104: "Refresh Success",
  };
  return `STUN: ${typeMap[msgType] || `Type=0x${msgType.toString(16).padStart(4, "0")}`}`;
}

/**
 * Summarize RIP messages.
 */
export function summarizeRIP(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "RIP packet";
  const view = new Uint8Array(payload);
  const command = view[0]; // 1=Request, 2=Response
  const version = view[1]; // 1=RIPv1, 2=RIPv2
  const cmdName = command === 1 ? "Request" : command === 2 ? "Response" : `Cmd=${command}`;
  const entryCount = Math.floor((payload.byteLength - 4) / 20);
  return `RIPv${version} ${cmdName}: ${entryCount} route entries`;
}
