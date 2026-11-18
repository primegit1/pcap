

/**
 * Build a human-readable summary for Modbus TCP payload.
 * Modbus TCP: MBAP header (7 bytes) + PDU (1 byte FC + data)
 */
export function summarizeModbus(payload: ArrayBuffer): string {
  if (payload.byteLength < 8) return "";
  const view = new Uint8Array(payload);
  const fc = view[7];
  const fcMap: Record<number, string> = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
    0x2B: "Encapsulated Interface Transport",
    0x2D: "CANopen Gateway",
    0x2E: "MODBUS Plus Gateway",
    0x41: "Read Device Identification",
  };
  const desc = fcMap[fc] ?? `Function Code 0x${fc.toString(16).padStart(2, "0")}`;
  return `${desc} (FC=0x${fc.toString(16).padStart(2, "0")})`;
}


/**
 * Parse DNP3 application layer function codes.
 */
export function summarizeDNP3(payload: ArrayBuffer): string {
  if (payload.byteLength < 18) return "";
  const view = new Uint8Array(payload);

  // DNP3 frame: 10 bytes header + user data
  // Check start bytes 0x0564
  if (view[0] !== 0x05 || view[1] !== 0x64) return "";

  // Application layer (after transport header, typically at offset 17 based on DNP3 structure)
  // For simplicity, look for the application header in the data area
  // Length of user data
  const userDataLen = payload.byteLength - 10;
  if (userDataLen < 4) return "DNP3";

  // Application layer at offset 10 (after 10-byte fixed header)
  const appOffset = 10;
  if (appOffset + 4 > payload.byteLength) return "DNP3";

  // DNP3 Application header: start(1) + appControl(1) + funcCode(1)
  // (appControl unused here, funcCode extracted via transportOffset below)

  // First byte after transport header should be 0xC0 (start of app layer) or similar
  // Check if we have DNP3 app layer start

  const fnMap: Record<number, string> = {
    0: "Confirm",
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate No Response",
    7: "Freeze",
    8: "Freeze Clear",
    9: "Freeze Clear No Response",
    10: "Freeze No Response",
    11: "Freeze Clear",
    12: "Assigned Class",
    13: "Event Data",
    14: "Poll Class 0",
    15: "Poll Class 1",
    16: "Poll Class 2",
    17: "Poll Class 3",
    18: "Event Buffer",
    19: "Log",
    20: "Assign Class",
    21: "Delay Measurement",
    22: "Record Current Time",
    23: "Open File",
    24: "Close File",
    25: "Delete File",
    26: "Get File Info",
    27: "Authenticate File",
    28: "Abort File Transfer",
    31: "Assign Class (Alt)",
    32: "Activate Configuration",
    33: "Authentication",
    34: "User Authentication",
    35: "Force Unsolicited",
    80: "Response",
    81: "Unsolicited Response",
    82: "Authentication Response",
    129: "Response (Alt)",
    130: "Unsolicited Response (Alt)",
    131: "Authentication Response (Alt)",
  };

  // Try to locate the app layer func code more precisely
  // DNP3 transport header is 2 bytes (userData[0]..userData[1])
  // Then the app header: appControl + funcCode + internalIndications(2)
  const transportOffset = view[10] & 0x40 ? 10 : 10; // transport header starts at offset 10
  if (payload.byteLength >= transportOffset + 3) {
    const tfn = view[transportOffset + 2];
    const fnName = fnMap[tfn] ?? `Func 0x${tfn.toString(16)}`;

    // Check for critical functions
    if (tfn === 3 || tfn === 4 || tfn === 5 || tfn === 6) {
      return `DNP3: ${fnName} [WRITE/OPERATE]`;
    }
    return `DNP3: ${fnName}`;
  }

  return "DNP3";
}


/**
 * Summarize EtherNet/IP / CIP command.
 */
export function summarizeEtherNetIP(payload: ArrayBuffer): string {
  if (payload.byteLength < 24) return "";
  const view = new Uint8Array(payload);

  // EtherNet/IP uses encapsulation header (24 bytes for UCMM, 28 for explicit msg)
  // Check command at bytes 0-1
  if (payload.byteLength >= 4) {
    const cmd = (view[0] << 8) | view[1];
    const cmdMap: Record<number, string> = {
      0x0001: "ListIdentity",
      0x0002: "ListServices",
      0x0003: "ListInterfaces", // v1 compat
      0x0004: "RegisterSession",
      0x0005: "UnregisterSession",
      0x0006: "SendRRData (Request/Response)",
      0x0007: "SendUnitData (Unconnected)",
      0x0008: "IndicateStatus",
      0x0009: "Cancel",
      0x004a: "SendUCMM (Unconnected Message)",
      0x0064: "ListTargets",
      0x0065: "ListTargetsAttributes",
      0x0066: "ListAttributes",
      0x0068: "ListServicesExtended",
    };

    // Length (unused but needed for parsing)
    const cmdName = cmdMap[cmd] ?? `Cmd 0x${cmd.toString(16)}`;

    if (cmd === 0x0004 || cmd === 0x0005) {
      // Register/Unregister Session
      if (payload.byteLength >= 8) {
        const sessionHandle = (view[4] << 24) | (view[5] << 16) | (view[6] << 8) | view[7];
        return `EtherNet/IP: ${cmdName} (session=0x${sessionHandle.toString(16)})`;
      }
    }

    // For explicit messaging, try to get CIP service
    if ((cmd === 0x0006 || cmd === 0x0007) && payload.byteLength >= 44) {
      // CIP header typically starts at offset 38-42 depending on encapsulation
      // Try offset 42 (common for SendRRData)
      const cipOffset = 42;
      if (payload.byteLength >= cipOffset + 2) {
        const cipService = view[cipOffset];
        const cipServiceMap: Record<number, string> = {
          0x01: "Get Attributes All",
          0x02: "Set Attributes All",
          0x03: "Get Attribute List",
          0x04: "Set Attribute List",
          0x05: "Reset",
          0x06: "Start",
          0x07: "Stop",
          0x08: "Create",
          0x09: "Delete",
          0x0a: "Multiple Service",
          0x0b: "Apply Attributes",
          0x0c: "Get Attribute Single",
          0x0d: "Set Attribute Single",
          0x0e: "Find Next Object Instance",
          0x0f: "Get Membership",
          0x10: "Remove Member",
          0x11: "Save",
          0x12: "Restore",
          0x14: "Get Enum String",
          0x15: "Get Enum Integer",
          0x16: "Get Connection Owner",
          0x4b: "Forward Open",
          0x4c: "Forward Close",
          0x52: "Unconnected Send",
          0x54: "Get Connection Data",
          0x55: "Search Connections",
        };
        const svcName = cipServiceMap[cipService] ?? `CIP Svc 0x${cipService.toString(16)}`;
        return `EtherNet/IP: ${cmdName} → ${svcName}`;
      }
    }

    return `EtherNet/IP: ${cmdName}`;
  }

  return "EtherNet/IP";
}


/**
 * Known OPC DA COM interface UUIDs (abstract syntax).
 * These appear in DCOM Bind/Alter Context PDUs on port 135.
 */
export const OPCDA_INTERFACE_UUIDS: Record<string, string> = {
  // Core OPC DA interfaces (OPC Data Access 2.x / 3.0)
  "39c13a4d-011e-11d0-9675-0020afd8adb3": "IOPCServer",
  "39c13a4e-011e-11d0-9675-0020afd8adb3": "IOPCServerPublicGroups",
  "39c13a4f-011e-11d0-9675-0020afd8adb3": "IOPCBrowseServerAddressSpace",
  "39c13a50-011e-11d0-9675-0020afd8adb3": "IOPCGroupStateMgt",
  "39c13a51-011e-11d0-9675-0020afd8adb3": "IOPCSyncIO",
  "39c13a52-011e-11d0-9675-0020afd8adb3": "IOPCAsyncIO",
  "39c13a53-011e-11d0-9675-0020afd8adb3": "IOPCItemMgt",
  "39c13a54-011e-11d0-9675-0020afd8adb3": "IOPCItemProperties",
  "39c13a55-011e-11d0-9675-0020afd8adb3": "IEnumOPCItemAttributes",
  "39c13a70-011e-11d0-9675-0020afd8adb3": "IOPCAsyncIO2",
  "39c13a71-011e-11d0-9675-0020afd8adb3": "IOPCGroupStateMgt2",
  "39c13a72-011e-11d0-9675-0020afd8adb3": "IOPCItemDeadbandMgt",
  "39c13a73-011e-11d0-9675-0020afd8adb3": "IOPCItemSamplingMgt",
  "85c0b427-2893-11d1-91d7-006008a013f4": "IOPCItemIO",
  "59480b20-635c-11d1-a1f2-006008c43fb9": "IOPCDataCallback",
  "39c13a63-011e-11d0-9675-0020afd8adb3": "IOPCShutdown",
  "39c13a64-011e-11d0-9675-0020afd8adb3": "IOPCCommon",
  // OPC DA 1.0
  "63e5f6e1-4741-11d1-9608-006008c43fb9": "IOPCServer (DA1.0)",
  "63e5f6e2-4741-11d1-9608-006008c43fb9": "IOPCGroupStateMgt (DA1.0)",
  "63e5f6e3-4741-11d1-9608-006008c43fb9": "IOPCSyncIO (DA1.0)",
  "63e5f6e4-4741-11d1-9608-006008c43fb9": "IOPCAsyncIO (DA1.0)",
  "63e5f6e5-4741-11d1-9608-006008c43fb9": "IOPCItemMgt (DA1.0)",
  // OPC DA enumerator
  "209d2c90-3f5d-11d1-9608-006008c43fb9": "IEnumUnknown",
  // OPC Server List (OPCENUM)
  "13486d50-4821-11d2-a494-3cb306c10000": "IOPCServerList",
  "13486d51-4821-11d2-a494-3cb306c10000": "IOPCServerList2",
  // Standard COM interfaces
  "00000131-0000-0000-c000-000000000046": "IRemUnknown",
  "00000143-0000-0000-c000-000000000046": "IRemUnknown2",
};


/**
 * Read a UUID from the DCOM Bind PDU at the given offset.
 * The first three fields (time_low, time_mid, time_hi_and_version) are
 * endian-swapped when the data representation is little-endian (byte 4 = 0x10).
 * The remaining 8 bytes (clock_seq + node) are always big-endian.
 */
export function readDCOMUUID(view: Uint8Array, offset: number, littleEndian: boolean): string | null {
  if (offset + 16 > view.length) return null;
  let tl: number, tm: number, th: number;
  if (littleEndian) {
    tl = view[offset] | (view[offset + 1] << 8) | (view[offset + 2] << 16) | (view[offset + 3] << 24);
    tm = view[offset + 4] | (view[offset + 5] << 8);
    th = view[offset + 6] | (view[offset + 7] << 8);
  } else {
    tl = (view[offset] << 24) | (view[offset + 1] << 16) | (view[offset + 2] << 8) | view[offset + 3];
    tm = (view[offset + 4] << 8) | view[offset + 5];
    th = (view[offset + 6] << 8) | view[offset + 7];
  }
  const hex = (n: number, width: number) => n.toString(16).padStart(width, "0");
  const rest = Array.from(view.slice(offset + 8, offset + 16))
    .map((b) => hex(b, 2))
    .join("");
  return `${hex(tl >>> 0, 8)}-${hex(tm, 4)}-${hex(th, 4)}-${rest.slice(0, 4)}-${rest.slice(4)}`;
}


/**
 * Extract interface names from a DCOM Bind or Alter Context PDU.
 * MS-RPC Bind: ctx list starts at offset 28, each ctx item has
 *   2-byte context ID + 1-byte num trans items + 1-byte reserved +
 *   20-byte abstract syntax (16 UUID + 4 version) +
 *   (num trans items × 20-byte transfer syntax entries).
 */
export function extractDCOMInterfaces(view: Uint8Array): string[] {
  if (view.length < 28) return [];
  const littleEndian = (view[4] & 0xf0) === 0x10; // data representation endianness
  const numCtxItems = view[24];
  const interfaces: string[] = [];
  let offset = 28;

  for (let i = 0; i < numCtxItems && offset + 24 <= view.length; i++) {
    offset += 4; // skip context ID (2) + num trans items (1) + reserved (1)
    if (offset + 20 > view.length) break;
    const uuid = readDCOMUUID(view, offset, littleEndian);
    if (uuid) {
      const name = OPCDA_INTERFACE_UUIDS[uuid];
      if (name) interfaces.push(name);
    }
    offset += 20; // abstract syntax UUID (16) + version (4)
    if (offset + 4 > view.length) break;
    const numTrans = view[offset - 16] ?? 1; // num trans items from ctx header
    offset += 20 * (Math.min(numTrans, 4)); // skip transfer syntax entries
  }

  return interfaces;
}


/**
 * Summarize OPC DA (Classic OPC / DCOM) traffic on port 135.
 * OPC DA uses DCOM/RPC as its transport. We detect DCOM bind and request
 * frames and identify common OPC DA interface UUIDs from Bind PDUs.
 */
export function summarizeOPCDA(payload: ArrayBuffer): string {
  if (payload.byteLength < 16) return "";
  const view = new Uint8Array(payload);

  if (view[0] === 0x05) {
    const pduType = view[2];
    const pduNames: Record<number, string> = {
      0x00: "Request",
      0x02: "Response",
      0x03: "Fault",
      0x0B: "Bind",
      0x0C: "Bind Ack",
      0x0D: "Bind Nak",
      0x0F: "Alter Context",
      0x10: "Alter Context Resp",
      0x11: "Shutdown",
      0x12: "Cancel",
    };
    const pduName = pduNames[pduType] ?? `PDU 0x${pduType.toString(16)}`;

    // Extract interface names from Bind / Alter Context PDUs
    if (pduType === 0x0b || pduType === 0x0f) {
      const ifaces = extractDCOMInterfaces(view);
      if (ifaces.length > 0) {
        return `OPC DA DCOM ${pduName} → ${ifaces.join(", ")}`;
      }
    }

    return `OPC DA DCOM ${pduName}`;
  }

  return "OPC DA (DCOM)";
}


/**
 * Summarize OPC UA binary protocol - detect message type and service details.
 */
export function summarizeOPCUA(payload: ArrayBuffer): string {
  if (payload.byteLength < 8) return "";
  const view = new Uint8Array(payload);

  if (payload.byteLength >= 3) {
    const msgType = String.fromCharCode(view[0], view[1], view[2]);
    const msgTypes: Record<string, string> = {
      "HEL": "HEL (Hello)",
      "ACK": "ACK (Acknowledge)",
      "ERR": "ERR (Error)",
      "OPN": "OPN (Open Secure Channel)",
      "CLO": "CLO (Close Secure Channel)",
      "MSG": "MSG (Message)",
      "RHE": "RHE (Re-Hello)",
    };
    const typeName = msgTypes[msgType] ?? `Type ${msgType}`;

    // OPN: extract security mode
    if (msgType === "OPN" && payload.byteLength >= 12) {
      const secMode = (view[12] << 24) | (view[13] << 16) | (view[14] << 8) | view[15];
      const secModes: Record<number, string> = {
        0x00: "None",
        0x01: "Sign",
        0x02: "SignAndEncrypt",
      };
      return `OPC UA ${typeName} security=${secModes[secMode] ?? `0x${secMode.toString(16)}`}`;
    }

    // ERR: extract error code
    if (msgType === "ERR" && payload.byteLength >= 24) {
      const errorCode = view[8] | (view[9] << 8) | (view[10] << 16) | (view[11] << 24);
      return `OPC UA ${typeName} code=0x${(errorCode >>> 0).toString(16)}`;
    }

    // MSG: attempt to extract the encoded service node ID
    // Binary encoding: MSG header (8) + security header + sequence header (8)
    // For SecurityMode=None: security header = 4-byte tokenId → body at offset 16
    // For Sign/SignAndEncrypt: body offset varies
    if (msgType === "MSG" && payload.byteLength >= 20) {
      for (const bodyOffset of [16, 24]) {
        if (bodyOffset >= payload.byteLength) continue;
        const serviceByte = view[bodyOffset];
        // Two-byte encoded NodeId: encoding byte + 2-byte node id
        if ((serviceByte & 0xf0) === 0x00 && payload.byteLength >= bodyOffset + 3) {
          const serviceId = view[bodyOffset + 1] | (view[bodyOffset + 2] << 8);
          const serviceNames: Record<number, string> = {
            428: "CreateSession",
            429: "CreateSessionResp",
            430: "ActivateSession",
            431: "ActivateSessionResp",
            432: "CloseSession",
            464: "Read",
            465: "ReadResp",
            472: "Write",
            473: "WriteResp",
            476: "HistoryRead",
            477: "HistoryReadResp",
            524: "Browse",
            525: "BrowseResp",
            528: "BrowseNext",
            529: "BrowseNextResp",
            532: "TranslateBrowsePaths",
            533: "TranslateBrowsePathsResp",
            564: "CreateSubscription",
            565: "CreateSubscriptionResp",
            568: "CreateMonitoredItems",
            569: "CreateMonitoredItemsResp",
            572: "ModifyMonitoredItems",
            580: "SetMonitoringMode",
            584: "Publish",
            585: "PublishResp",
            588: "Republish",
            672: "Call",
            673: "CallResp",
            674: "GetEndpoints",
            675: "GetEndpointsResp",
            678: "FindServers",
            679: "FindServersResp",
            11492: "RegisterServer",
            12211: "RegisterServer2",
          };
          const svcName = serviceNames[serviceId];
          if (svcName) return `OPC UA MSG ${svcName} (0x${serviceId.toString(16)})`;
          return `OPC UA MSG Service 0x${serviceId.toString(16)}`;
        }
        // Four-byte encoded NodeId: 0x01 prefix + 2-byte namespace + 2-byte id
        if (serviceByte === 0x01 && payload.byteLength >= bodyOffset + 5) {
          const serviceId = view[bodyOffset + 3] | (view[bodyOffset + 4] << 8);
          return `OPC UA MSG Service 0x${serviceId.toString(16)}`;
        }
      }
      return `OPC UA ${typeName}`;
    }

    return `OPC UA ${typeName}`;
  }

  return "OPC UA";
}


/**
 * Summarize IEC 60870-5-104 (IEC 104) - APCI type detection.
 */
export function summarizeIEC104(payload: ArrayBuffer): string {
  if (payload.byteLength < 6) return "";
  const view = new Uint8Array(payload);

  // IEC 104 APCI: start byte 0x68
  if (view[0] !== 0x68) return "IEC 104";
  if (payload.byteLength < 6) return "IEC 104";

  const apduLen = view[1];
  if (apduLen < 4 || apduLen + 2 > payload.byteLength) return "IEC 104";

  // Control field (3 bytes for I/S, 2 bytes for U)
  const controlByte1 = view[2];
  const controlByte2 = view[3];

  // U-format: controlByte1 has bits 0x03 set
  if ((controlByte1 & 0x03) !== 0) {
    // STARTDT = 0x01, STOPDT = 0x02, TESTFR = 0x80|0x02|0x01 = 0x83
    if (controlByte1 === 0x07 && (controlByte2 & 0x80)) {
      return "IEC 104: STARTDT_CON (Confirm)";
    }
    if (controlByte1 === 0x07 && !(controlByte2 & 0x80)) {
      return "IEC 104: STOPDT_CON (Confirm)";
    }
    if (controlByte1 === 0x07) return "IEC 104: STARTDT_ACT (Activate)";
    if (controlByte1 === 0x83) return "IEC 104: TESTFR_ACT (Activate)";
    if ((controlByte2 & 0x80) && controlByte1 === 0x03) return "IEC 104: TESTFR_CON (Confirm)";
    if (controlByte1 === 0x01) return "IEC 104: STARTDT_ACT (Activate)";
    if (controlByte1 === 0x02) return "IEC 104: STOPDT_ACT (Activate)";
    // Try by matching bits
    if ((controlByte1 & 0x80)) return "IEC 104: TESTFR_ACT (Activate)";
    return "IEC 104: U-Format";
  }

  // S-format (Supervisory): bit pattern 0x0001
  if ((controlByte1 & 0x03) === 0x01 || (controlByte1 & 0x03) === 0x00 && controlByte2 === 0x00) {
    // Check if really S-format: controlByte2 bits 1-7 should be 0
    if ((controlByte2 & 0xfe) === 0x00) {
      return "IEC 104: S-Format (Supervisory/ACK)";
    }
  }

  // Check bit 0 = 0 for I-format
  if ((controlByte1 & 0x01) === 0) {
    // I-format (Information): contains ASDU
    // ASDU starts at offset 6 (after start+length+3 control bytes)
    if (payload.byteLength >= 8) {
      const asduOffset = 6;
      if (payload.byteLength >= asduOffset + 2) {
        const typeId = view[asduOffset];
        const typeMap: Record<number, string> = {
          1: "M_SP_NA (Single-Point Info)",
          2: "M_SP_TA (Single-Point Time)",
          3: "M_DP_NA (Double-Point Info)",
          4: "M_DP_TA (Double-Point Time)",
          5: "M_ST_NA (Step Position)",
          6: "M_ST_TA (Step Position Time)",
          7: "M_BO_NA (Binary Counter)",
          8: "M_BO_TA (Binary Counter Time)",
          9: "M_ME_NA (Measured Value)",
          10: "M_ME_TA (Measured Value Time)",
          11: "M_ME_NB (Measured Value (Scaled))",
          12: "M_ME_TB (Measured Value Scaled Time)",
          13: "M_ME_NC (Measured Value (Float))",
          14: "M_ME_TC (Measured Value Float Time)",
          15: "M_IT_NA (Integrated Totals)",
          16: "M_IT_TA (Integrated Totals Time)",
          17: "M_EP_TA (Event Time)",
          18: "M_EP_TB (Packed Event Time)",
          19: "M_EP_TC (Packed Event Time with CP56Time2a)",
          20: "M_PS_NA (Single-Point Status)",
          21: "M_PS_TA (Single-Point Status Time)",
          22: "M_ME_ND (Measured Value (Short Float))",
          23: "M_SP_TB (Single-Point Time CP56)",
          24: "M_DP_TB (Double-Point Time CP56)",
          25: "M_ST_TB (Step Position Time CP56)",
          26: "M_BO_TB (Binary Counter Time CP56)",
          27: "M_ME_TD (Measured Value Time CP56)",
          28: "M_ME_TE (Measured Value Scaled CP56)",
          29: "M_ME_TF (Measured Value Float CP56)",
          30: "M_IT_TB (Integrated Totals CP56)",
          31: "M_EP_TD (Event Time CP56)",
          32: "M_EP_TE (Packed Event CP56)",
          33: "M_EP_TF (Packed Event CP56 Time)",
          34: "M_SP_TF (Single-Point Time CP56)",
          35: "M_DP_TF (Double-Point Time CP56)",
          45: "C_SC_NA (Single Command)",
          46: "C_DC_NA (Double Command)",
          47: "C_RC_NA (Regulating Command)",
          48: "C_SE_NA (Setpoint Command (Scaled))",
          49: "C_SE_NB (Setpoint Command (Float))",
          50: "C_SE_NC (Setpoint Command (Boolean))",
          51: "C_BO_NA (Bitstring Command)",
          58: "C_IC_NA (Interrogation Command)",
          59: "C_CI_NA (Counter Interrogation)",
          60: "C_RD_NA (Read Command)",
          61: "C_CS_NA (Clock Sync)",
          62: "C_TS_NA (Test Command)",
          63: "C_RP_NA (Reset Process)",
          64: "C_CD_NA (Delay Acquisition)",
          70: "C_TS_NB (Clock Sync (Fine))",
          100: "C_OT_NA (Parameter Threshold)",
          101: "C_OS_NA (Parameter Setpoint)",
          102: "C_OL_NA (Parameter Filter)",
          103: "C_OT_NB (Parameter Threshold Extended)",
          110: "E_SQ_NA (End of Session)",
          120: "F_FR_NA (File Ready)",
          121: "F_SR_NA (Section Ready)",
          122: "F_LS_NA (Last Segment)",
          123: "F_AF_NA (Acknowledge File)",
          124: "F_SG_NA (Segment)",
          125: "F_DR_NA (Directory)",
          126: "F_SC_NA (Summarize Call Directory)",
        };
        const typeName = typeMap[typeId] ?? `TypeID ${typeId}`;
        // Check if command (45-64, 70-102 range — control functions)
        if ((typeId >= 45 && typeId <= 64) || (typeId >= 100 && typeId <= 103)) {
          return `IEC 104: ${typeName} [COMMAND]`;
        }
        return `IEC 104: ${typeName}`;
      }
    }
    return "IEC 104: I-Format (Data)";
  }

  return "IEC 104";
}


/**
 * Summarize S7Comm payload.
 */
export function summarizeS7(payload: ArrayBuffer): string {
  if (payload.byteLength < 7) return "";
  const view = new Uint8Array(payload);
  let offset = 0;

  // Try to skip TPKT header (4 bytes) if present
  if (payload.byteLength >= 4 && view[0] === 0x03 && view[1] === 0x00) {
    offset = 4;
  }

  // Skip COTP header
  if (offset + 2 <= payload.byteLength) {
    const cotpLen = view[offset];
    offset += 1 + cotpLen;
  }

  // S7 PDU
  if (offset + 2 > payload.byteLength) return "";
  const s7Magic = view[offset];
  if (s7Magic === 0x32) {
    const s7Function = offset + 2 < payload.byteLength ? view[offset + 2] : 0;
    const fnMap: Record<number, string> = {
      0x00: "CPU Communication",
      0x01: "Read",
      0x02: "Write",
      0x04: "Request/Data",
      0x05: "Enumerate",
      0x07: "Block Functions",
      0x0f: "Security",
      0x10: "PLC Control",
      0x1c: "Time Functions",
      0x1d: "Upload/Download",
    };
    const desc = fnMap[s7Function] ?? `Function 0x${s7Function.toString(16)}`;

    // For PLC control, detect specific sub-commands
    if (s7Function === 0x10 && offset + 7 < payload.byteLength) {
      const sub = view[offset + 7];
      const subMap: Record<number, string> = {
        0x01: "STOP",
        0x02: "START",
        0x03: "HOT RESTART",
      };
      const subName = subMap[sub] ?? `Sub 0x${sub.toString(16)}`;
      return `S7 ${desc}: ${subName}`;
    }

    return `S7 ${desc}`;
  }
  return "";
}


/**
 * Summarize BACnet payload.
 */
export function summarizeBACnet(payload: ArrayBuffer): string {
  if (payload.byteLength < 6) return "";
  const view = new Uint8Array(payload);
  let pos = 0;
  if (payload.byteLength >= 4) {
    const bvlcType = view[pos];
    pos++;
    // Skip bvlcFunction (1 byte) + length (2 bytes)
    pos += 3;
    if (bvlcType === 0x81) {
      const apduType = pos < payload.byteLength ? (view[pos] >> 4) & 0x0f : 0;
      const apduTypes: Record<number, string> = {
        0x0: "ConfirmedReq",
        0x1: "UnconfirmedReq",
        0x2: "SimpleAck",
        0x3: "ComplexAck",
        0x4: "SegmentAck",
        0x5: "Error",
        0x6: "Reject",
        0x7: "Abort",
      };
      // For confirmed/unconfirmed requests, try to get service choice
      let svcDesc = "";
      if ((apduType === 0x00 || apduType === 0x01) && pos + 1 < payload.byteLength) {
        const svcChoice = view[pos];
        const svcMap: Record<number, string> = {
          0x00: "acknowledgeAlarm",
          0x01: "confirmedCOVNotification",
          0x02: "confirmedEventNotification",
          0x03: "getAlarmSummary",
          0x04: "getEnrollmentSummary",
          0x05: "subscribeCOV",
          0x06: "atomicReadFile",
          0x07: "atomicWriteFile",
          0x08: "addListElement",
          0x09: "removeListElement",
          0x0a: "createObject",
          0x0b: "deleteObject",
          0x0c: "readProperty",
          0x0d: "readPropertyConditional",
          0x0e: "readPropertyMultiple",
          0x0f: "writeProperty",
          0x10: "writePropertyMultiple",
          0x11: "deviceCommunicationControl",
          0x12: "confirmedPrivateTransfer",
          0x13: "confirmedTextMessage",
          0x14: "reinitializeDevice",
          0x15: "vtOpen",
          0x16: "vtClose",
          0x17: "vtData",
          0x18: "authenticate",
          0x19: "requestKey",
          0x1a: "iAm",
          0x1b: "iHave",
          0x1c: "unconfirmedCOVNotification",
          0x1d: "unconfirmedEventNotification",
          0x1e: "unconfirmedPrivateTransfer",
          0x1f: "unconfirmedTextMessage",
          0x20: "timeSynchronization",
          0x21: "whoHas",
          0x22: "whoIs",
          0x23: "utcTimeSynchronization",
          0x24: "writeGroup",
          0x25: "subscribeCOVProperty",
          0x26: "getEventInformation",
          0x27: "subscribeCOVPropertyMultiple",
          0x28: "confirmedCOVNotificationMultiple",
          0x29: "unconfirmedCOVNotificationMultiple",
        };
        svcDesc = svcMap[svcChoice] ?? `Svc=0x${svcChoice.toString(16)}`;
      }
      return `BACnet ${apduTypes[apduType] ?? `APDU=0x${apduType.toString(16)}`}${svcDesc ? `:${svcDesc}` : ""}`;
    }
  }
  return "";
}


/**
 * Summarize Profinet payload.
 */
export function summarizeProfinet(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "";
  const view = new Uint8Array(payload);
  const frameId = (view[0] << 8) | view[1];
  let desc: string;
  if (frameId >= 0x8000 && frameId <= 0x83ff) desc = "PTCP (Precision Transparent Clock)";
  else if (frameId >= 0x0100 && frameId <= 0x01ff) desc = "RTA / DIO (Cyclic I/O Data)";
  else if (frameId >= 0xf800 && frameId <= 0xfbff) desc = "Alarm";
  else if (frameId >= 0xfc00 && frameId <= 0xfeff) desc = "RTA Multicast/Broadcast";
  else if (frameId >= 0x0020 && frameId <= 0x003f) desc = "DCE/RPC (Configuration)";
  else desc = "RTA Data";
  return `${desc} (FrameID=0x${frameId.toString(16).padStart(4, "0")})`;
}

/**
 * Summarize Foundation Fieldbus LAN Redundancy (FF-LR) payload on port 3622.
 */
export function summarizeFFLR(payload: ArrayBuffer): string {
  if (payload.byteLength === 0) return "FF-LR Heartbeat/Sync";
  if (payload.byteLength < 4) return `FF-LR (${payload.byteLength} bytes)`;
  const view = new Uint8Array(payload);
  const msgType = view[0];
  const typeMap: Record<number, string> = {
    0x01: "Heartbeat",
    0x02: "Status Query",
    0x03: "Status Response",
    0x04: "Failover Trigger",
    0x05: "Sync State",
  };
  const typeDesc = typeMap[msgType] ? ` (${typeMap[msgType]})` : "";
  return `FF-LR Redundancy Msg${typeDesc} [${payload.byteLength} bytes]`;
}
