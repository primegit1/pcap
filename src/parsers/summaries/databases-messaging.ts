import { firstLineAsText } from "./shared";

/**
 * Summarize MSSQL payload.
 */
export function summarizeMSSQL(payload: ArrayBuffer): string {
  if (payload.byteLength < 8) return "";
  const view = new Uint8Array(payload);
  const tdsTypes: Record<number, string> = {
    0x01: "SQL Batch",
    0x02: "Pre-TDS7 Login",
    0x03: "RPC",
    0x04: "Tabular Result",
    0x06: "Attention Signal",
    0x07: "Bulk Load",
    0x0e: "Transaction Manager Request",
    0x10: "Login 7",
    0x11: "SSPI",
    0x12: "Pre-Login",
  };
  const typeName = tdsTypes[view[0]] ?? `TDS type=0x${view[0].toString(16)}`;
  return typeName;
}


/* ───────── New protocol summarizers ───────── */

/**
 * Summarize MQTT — parse CONNECT/SUBSCRIBE/PUBLISH from the fixed header.
 */
export function summarizeMQTT(payload: ArrayBuffer): string {
  if (payload.byteLength < 2) return "MQTT";
  const view = new Uint8Array(payload);
  const msgType = (view[0] >> 4) & 0x0f;
  const typeMap: Record<number, string> = {
    1:  "CONNECT",
    2:  "CONNACK",
    3:  "PUBLISH",
    4:  "PUBACK",
    5:  "PUBREC",
    6:  "PUBREL",
    7:  "PUBCOMP",
    8:  "SUBSCRIBE",
    9:  "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
  };
  const name = typeMap[msgType] ?? `Type ${msgType}`;
  return `MQTT ${name}`;
}


/**
 * Summarize Redis — parse text protocol commands and responses.
 */
export function summarizeRedis(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 120);
  if (!text) return "Redis";
  // Redis RESP: +OK, -ERR, :integer, $bulk, *array
  const prefix = text[0];
  const respTypes: Record<string, string> = {
    "+": "Simple String",
    "-": "Error",
    ":": "Integer",
    "$": "Bulk String",
    "*": "Array",
  };
  if (respTypes[prefix]) {
    return `Redis ${respTypes[prefix]}: ${text.slice(1, 80).trim()}`;
  }
  // Inline command
  return `Redis: ${text.slice(0, 60)}`;
}


/**
 * Summarize Memcached — parse text commands (get/set/stats/etc).
 */
export function summarizeMemcached(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 80);
  if (!text) return "Memcached";
  const upper = text.toUpperCase();
  const cmd = upper.split(/\s/)[0];
  const cmdMap: Record<string, string> = {
    "GET": "get", "GETS": "gets", "SET": "set", "ADD": "add",
    "REPLACE": "replace", "APPEND": "append", "PREPEND": "prepend",
    "CAS": "cas", "DELETE": "delete", "INCR": "incr", "DECR": "decr",
    "STATS": "stats", "FLUSH_ALL": "flush_all", "VERSION": "version",
    "QUIT": "quit", "TOUCH": "touch", "GAT": "gat",
  };
  const desc = cmdMap[cmd] ?? `cmd ${cmd}`;
  return `Memcached ${desc}`;
}


/**
 * Summarize MySQL — parse protocol version and handshake.
 */
export function summarizeMySQL(payload: ArrayBuffer): string {
  if (payload.byteLength < 5) return "MySQL";
  const view = new Uint8Array(payload);

  // MySQL packet: 3-byte length + 1-byte sequence number
  const pktLen = view[0] | (view[1] << 8) | (view[2] << 16);
  const seq = view[3];

  if (payload.byteLength >= 5) {
    // Server greeting: starts with protocol version (0x0a = MySQL 5.x, 0x09 = 4.x)
    if (view[4] === 0x0a || view[4] === 0x09) {
      // Extract server version string (null-terminated after protocol version)
      let end = 5;
      while (end < Math.min(payload.byteLength, 100) && view[end] !== 0x00) end++;
      const verStr = String.fromCharCode(...Array.from(view.slice(5, end)));
      return `MySQL Server Greeting v${verStr}`;
    }
    // Client auth — check capability flags
    if (seq === 1 && pktLen > 0) {
      return "MySQL Client Auth";
    }
  }
  return `MySQL (seq ${seq}, len ${pktLen})`;
}


/**
 * Summarize PostgreSQL — parse startup/query messages.
 */
export function summarizePostgreSQL(payload: ArrayBuffer): string {
  if (payload.byteLength < 5) return "PostgreSQL";
  const view = new Uint8Array(payload);
  const tag = String.fromCharCode(view[0]);
  // PG wire protocol: 1-byte tag + 4-byte length
  const tagMap: Record<string, string> = {
    "\x00\x00\x00": "Startup (SSL)",
    "Q": "Simple Query",
    "P": "Parse",
    "B": "Bind",
    "E": "Execute",
    "D": "Describe / Data Row",
    "C": "Close",
    "S": "Sync",
    "R": "Authentication Response",
    "K": "Backend Key Data",
    "T": "Row Description",
    "Z": "Ready for Query",
    "N": "Notice Response",
  };
  const name = tagMap[tag] ?? `tag ${tag}`;
  return `PostgreSQL ${name}`;
}


/**
 * Summarize MongoDB — detect OP_MSG/OP_QUERY type from header.
 */
export function summarizeMongoDB(payload: ArrayBuffer): string {
  if (payload.byteLength < 16) return "MongoDB";
  const view = new Uint8Array(payload);
  const msgLen = view[0] | (view[1] << 8) | (view[2] << 16) | (view[3] << 24);
  if (payload.byteLength >= 20) {
    const opCode = view[12] | (view[13] << 8) | (view[14] << 16) | (view[15] << 24);
    const opMap: Record<number, string> = {
      1: "OP_REPLY", 2001: "OP_UPDATE", 2002: "OP_INSERT",
      2004: "OP_QUERY", 2005: "OP_GET_MORE", 2006: "OP_DELETE",
      2007: "OP_KILL_CURSORS", 2013: "OP_MSG",
    };
    return `MongoDB ${opMap[opCode] ?? `Op 0x${opCode.toString(16)}`} (${msgLen}B)`;
  }
  return `MongoDB (${msgLen}B)`;
}


/**
 * Summarize Oracle TNS (Transparent Network Substrate) payload.
 * TNS packets: 8-byte common header + data.
 * Packet types: 1=Connect, 2=Accept, 3=Acknowledge, 4=Refuse, 6=Data, 11=Redirect, 12=Marker
 */
export function summarizeOracleTNS(payload: ArrayBuffer): string {
  if (payload.byteLength < 8) return "Oracle TNS";
  const view = new Uint8Array(payload);

  const pktType = view[4];
  const typeNames: Record<number, string> = {
    1: "Connect",
    2: "Accept",
    3: "Acknowledge",
    4: "Refuse",
    6: "Data",
    7: "Redirect",
    9: "Control",
    11: "Marker",
    12: "Attention",
    14: "Data (OOB)",
  };

  const typeName = typeNames[pktType] ?? `Type ${pktType}`;

  if (pktType === 1 && payload.byteLength > 26) {
    // Connect: contains community string and connect data
    let text = "";
    for (let i = 26; i < Math.min(view.length, 120); i++) {
      const ch = view[i];
      if (ch >= 0x20 && ch <= 0x7e) text += String.fromCharCode(ch);
      else if (ch === 0) break;
    }
    if (text.length > 0) {
      // Truncate at first non-printable
      const clean = text.substring(0, 80);
      return `Oracle TNS Connect → ${clean}`;
    }
  }

  return `Oracle TNS ${typeName}`;
}


/**
 * Summarize AMQP (Advanced Message Queuing Protocol) payload.
 * AMQP 0-9-1: 1-byte type + 2-byte channel + 4-byte body size
 * AMQP 1.0: Different framing (0x00 type prefix)
 * Types: 1=METHOD, 2=HEADER, 3=BODY, 4=HEARTBEAT
 */
export function summarizeAMQP(payload: ArrayBuffer): string {
  if (payload.byteLength < 8) return "AMQP";
  const view = new Uint8Array(payload);

  // Check for AMQP protocol header "AMQP" (connection negotiation)
  if (payload.byteLength >= 8 &&
      view[0] === 0x41 && view[1] === 0x4d && view[2] === 0x51 && view[3] === 0x50) {
    const major = view[4];
    const minor = view[5];
    const revision = view[6];
    return `AMQP ${major}.${minor}.${revision} Header`;
  }

  // AMQP 1.0 open frame starts with 0x00
  if (view[0] === 0x00) {
    return "AMQP 1.0";
  }

  // AMQP 0-9-1 frame
  const frameType = view[0];
  const channel = (view[1] << 8) | view[2];

  const typeNames: Record<number, string> = {
    1: "Method",
    2: "Content Header",
    3: "Content Body",
    4: "Heartbeat",
  };

  const typeName = typeNames[frameType] ?? `Frame ${frameType}`;

  if (frameType === 1 && payload.byteLength >= 12) {
    // Method frame: class ID + method ID
    const classId = (view[7] << 8) | view[8];
    const methodId = (view[9] << 8) | view[10];

    const methodNames: Record<string, string> = {
      "10.10": "Connection.Start",
      "10.11": "Connection.Start-Ok",
      "10.20": "Connection.Secure",
      "10.21": "Connection.Secure-Ok",
      "10.30": "Connection.Tune",
      "10.31": "Connection.Tune-Ok",
      "10.40": "Connection.Open",
      "10.41": "Connection.Open-Ok",
      "10.50": "Connection.Close",
      "10.51": "Connection.Close-Ok",
      "20.10": "Channel.Open",
      "20.11": "Channel.Open-Ok",
      "40.10": "Exchange.Declare",
      "40.11": "Exchange.Declare-Ok",
      "50.10": "Queue.Declare",
      "50.11": "Queue.Declare-Ok",
      "60.20": "Basic.Consume",
      "60.21": "Basic.Consume-Ok",
      "60.40": "Basic.Publish",
      "60.50": "Basic.Return",
      "60.60": "Basic.Deliver",
      "60.70": "Basic.Get",
      "60.71": "Basic.Get-Ok",
      "60.80": "Basic.Ack",
      "60.90": "Basic.Nack",
    };

    const key = `${classId}.${methodId}`;
    const methodName = methodNames[key] ?? `Class ${classId} Method ${methodId}`;
    return `AMQP ${methodName} (ch ${channel})`;
  }

  return `AMQP ${typeName} (ch ${channel})`;
}
