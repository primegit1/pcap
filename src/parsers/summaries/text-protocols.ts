import { firstLineAsText } from "./shared";

/* ───────── Protocol-specific summarizers ───────── */

/**
 * Build a human-readable summary of the application payload for HTTP requests/responses.
 */
export function summarizeHTTP(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 300);
  if (!text) return "";
  return text;
}


/**
 * Parse FTP command/reply. First 4 chars typically indicate the command.
 */
export function summarizeFTP(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 200);
  if (!text) return "";
  const upper = text.toUpperCase();
  const cmdMap: Record<string, string> = {
    "USER": "USER (Username)",
    "PASS": "PASS (Password)",
    "ACCT": "ACCT (Account)",
    "CWD":  "CWD (Change Working Dir)",
    "CDUP": "CDUP (Change to Parent)",
    "SMNT": "SMNT (Structure Mount)",
    "QUIT": "QUIT (Logout)",
    "REIN": "REIN (Reinitialize)",
    "PORT": "PORT (Data Port)",
    "PASV": "PASV (Passive Mode)",
    "TYPE": "TYPE (Transfer Type)",
    "STRU": "STRU (File Structure)",
    "MODE": "MODE (Transfer Mode)",
    "RETR": "RETR (Download)",
    "STOR": "STOR (Upload)",
    "STOU": "STOU (Unique Upload)",
    "APPE": "APPE (Append)",
    "ALLO": "ALLO (Allocate)",
    "REST": "REST (Restart)",
    "RNFR": "RNFR (Rename From)",
    "RNTO": "RNTO (Rename To)",
    "ABOR": "ABOR (Abort)",
    "DELE": "DELE (Delete)",
    "RMD":  "RMD (Remove Dir)",
    "MKD":  "MKD (Make Dir)",
    "PWD":  "PWD (Print Working Dir)",
    "LIST": "LIST (Directory Listing)",
    "NLST": "NLST (Name List)",
    "SITE": "SITE (Site Parameters)",
    "SYST": "SYST (System Type)",
    "STAT": "STAT (Status)",
    "HELP": "HELP (Help)",
    "NOOP": "NOOP (No-Op)",
    "AUTH": "AUTH (Authentication/Security)",
    "PROT": "PROT (Data Channel Protection)",
    "PBSZ": "PBSZ (Protection Buffer Size)",
  };
  // Check if it's a reply (starts with 3 digits)
  const replyMatch = text.match(/^(\d{3})([ -])(.*)/);
  if (replyMatch) {
    const code = parseInt(replyMatch[1], 10);
    const codeNames: Record<number, string> = {
      110: "Restart Marker",
      120: "Service Ready Soon",
      125: "Data Connection Open",
      150: "File Status OK",
      200: "Command OK",
      202: "Command Not Implemented",
      211: "System Status",
      212: "Directory Status",
      213: "File Status",
      214: "Help Message",
      220: "Service Ready",
      221: "Service Closing",
      225: "Data Connection Open",
      226: "Closing Data Connection",
      227: "Entering Passive Mode",
      228: "Long Passive Mode",
      229: "Extended Passive Mode",
      230: "User Logged In",
      231: "User Logged Out",
      232: "Logout Noted",
      234: "AUTH Mechanism OK",
      250: "File Action OK",
      257: "Path Created",
      331: "Username OK, Need Password",
      332: "Need Account",
      350: "Pending Further Info",
      421: "Service Not Available",
      425: "Data Connection Failed",
      426: "Connection Closed",
      430: "Invalid Username/Password",
      434: "Host Unavailable",
      450: "File Unavailable",
      451: "Local Error",
      452: "Insufficient Space",
      500: "Syntax Error",
      501: "Syntax Error in Params",
      502: "Command Not Implemented",
      503: "Bad Sequence",
      504: "Param Not Implemented",
      530: "Not Logged In",
      532: "Need Account",
      550: "File Unavailable",
      551: "Page Type Unknown",
      552: "Storage Allocation Exceeded",
      553: "Filename Not Allowed",
    };
    const name = codeNames[code] ?? `Reply ${code}`;
    return `${text.slice(0, 60)} [${name}]`;
  }

  const cmd = upper.slice(0, 4).trim();
  const cmdName = cmdMap[cmd];
  if (cmdName) {
    const arg = text.slice(cmd.length + 1, 60).trim();
    return arg ? `${cmdName}: ${arg}` : cmdName;
  }
  return text.slice(0, 80);
}


/**
 * Parse Telnet IAC (Interpret As Command) negotiations.
 */
export function summarizeTelnet(payload: ArrayBuffer): string {
  const view = new Uint8Array(payload);
  if (view.length === 0) return "";

  // Telnet IAC negotiation starts with 0xFF
  if (view[0] === 0xff && view.length >= 3) {
    const cmdCodes: Record<number, string> = {
      240: "SE (End of Subnegotiation)",
      241: "NOP (No-Op)",
      242: "Data Mark",
      243: "Break",
      244: "Interrupt Process",
      245: "Abort Output",
      246: "Are You There",
      247: "Erase Character",
      248: "Erase Line",
      249: "Go Ahead",
      250: "SB (Subnegotiation Begin)",
      251: "WILL",
      252: "WONT",
      253: "DO",
      254: "DONT",
      255: "IAC",
    };
    const optionCodes: Record<number, string> = {
      0: "Binary Transmission",
      1: "Echo",
      3: "Suppress Go Ahead",
      5: "Status",
      6: "Timing Mark",
      24: "Terminal Type",
      31: "Window Size",
      32: "Terminal Speed",
      33: "Remote Flow Control",
      34: "Line Mode",
      36: "Environment",
      39: "New Environment",
      46: "X Display Location",
    };

    const cmd = view[1];
    const cmdName = cmdCodes[cmd] ?? `Cmd 0x${cmd.toString(16)}`;
    if (view.length >= 3) {
      const opt = view[2];
      const optName = optionCodes[opt] ?? `Opt 0x${opt.toString(16)}`;
      return `IAC ${cmdName} ${optName}`;
    }
    return `IAC ${cmdName}`;
  }

  // Regular text — show first line
  const text = firstLineAsText(payload, 200);
  return text ? `Data: ${text.slice(0, 60)}` : "";
}


/**
 * Parse SMTP commands and reply codes.
 */
export function summarizeSMTP(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 200);
  if (!text) return "";
  const upper = text.toUpperCase();

  // Reply code
  const replyMatch = text.match(/^(\d{3})([ -])(.*)/);
  if (replyMatch) {
    const code = parseInt(replyMatch[1], 10);
    const codeNames: Record<number, string> = {
      211: "System Status",
      214: "Help",
      220: "Service Ready",
      221: "Service Closing",
      235: "Authentication Succeeded",
      250: "Requested Action OK",
      251: "User Not Local",
      252: "Cannot Verify User",
      334: "Auth Challenge",
      354: "Start Mail Input",
      421: "Service Not Available",
      450: "Mailbox Unavailable",
      451: "Local Error",
      452: "Insufficient Storage",
      500: "Syntax Error",
      501: "Syntax Error in Params",
      502: "Command Not Implemented",
      503: "Bad Command Sequence",
      504: "Parameter Not Implemented",
      535: "Authentication Failed",
      550: "Mailbox Unavailable",
      551: "User Not Local",
      552: "Storage Exceeded",
      553: "Mailbox Name Invalid",
      554: "Transaction Failed",
    };
    const name = codeNames[code] ?? `Reply ${code}`;
    const msg = replyMatch[3].slice(0, 50);
    return msg ? `${code} ${name}: ${msg}` : `${code} ${name}`;
  }

  // Command
  const cmdMap: Record<string, string> = {
    "HELO": "HELO (Greeting)",
    "EHLO": "EHLO (Extended Greeting)",
    "MAIL FROM": "MAIL FROM (Sender)",
    "MAIL": "MAIL (Sender)",
    "RCPT TO": "RCPT TO (Recipient)",
    "RCPT": "RCPT (Recipient)",
    "DATA": "DATA (Message Body)",
    "RSET": "RSET (Reset)",
    "VRFY": "VRFY (Verify)",
    "EXPN": "EXPN (Expand)",
    "QUIT": "QUIT (Logout)",
    "AUTH": "AUTH (Authentication)",
    "STARTTLS": "STARTTLS (TLS Upgrade)",
    "NOOP": "NOOP (No-Op)",
    "HELP": "HELP (Help)",
  };
  for (const [prefix, desc] of Object.entries(cmdMap)) {
    if (upper.startsWith(prefix)) {
      const arg = text.slice(prefix.length + 1, 80).trim();
      return arg ? `${desc}: ${arg}` : desc;
    }
  }
  return text.slice(0, 80);
}


/**
 * Parse IMAP commands and responses.
 */
export function summarizeIMAP(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 200);
  if (!text) return "";

  // IMAP commands are typically tagged: a001 LOGIN user pass
  const cmdMatch = text.match(/^[a-z0-9]+\s+(\w+)\s*(.*)/i);
  if (cmdMatch) {
    const cmd = cmdMatch[1].toUpperCase();
    const cmdMap: Record<string, string> = {
      "LOGIN":    "LOGIN (Authenticate)",
      "LOGOUT":   "LOGOUT",
      "CAPABILITY":"CAPABILITY",
      "SELECT":   "SELECT (Open Mailbox)",
      "EXAMINE":  "EXAMINE (Read-Only Mailbox)",
      "CREATE":   "CREATE (Create Mailbox)",
      "DELETE":   "DELETE (Delete Mailbox)",
      "RENAME":   "RENAME (Rename Mailbox)",
      "SUBSCRIBE":"SUBSCRIBE",
      "UNSUBSCRIBE":"UNSUBSCRIBE",
      "LIST":     "LIST (List Mailboxes)",
      "LSUB":     "LSUB (List Subscribed)",
      "STATUS":   "STATUS (Mailbox Status)",
      "APPEND":   "APPEND (Upload Message)",
      "CHECK":    "CHECK (Checkpoint)",
      "CLOSE":    "CLOSE (Close & Expunge)",
      "EXPUNGE":  "EXPUNGE (Permanently Remove)",
      "SEARCH":   "SEARCH (Search Messages)",
      "FETCH":    "FETCH (Retrieve Message)",
      "STORE":    "STORE (Modify Flags)",
      "COPY":     "COPY (Copy Message)",
      "MOVE":     "MOVE (Move Message)",
      "UID":      "UID (UID Command)",
      "IDLE":     "IDLE (Idle)",
      "NAMESPACE":"NAMESPACE",
      "GETQUOTA": "GETQUOTA",
      "SETQUOTA": "SETQUOTA",
      "ENABLE":   "ENABLE",
      "COMPRESS": "COMPRESS (Deflate)",
      "AUTHENTICATE":"AUTHENTICATE",
      "STARTTLS": "STARTTLS",
    };
    const desc = cmdMap[cmd] ?? `Command ${cmd}`;
    // Don't show LOGIN credentials in the summary
    if (cmd === "LOGIN") {
      return `${desc} (credentials hidden)`;
    }
    const args = cmdMatch[2].slice(0, 60);
    return args ? `${desc}: ${args}` : desc;
  }

  // Untagged response: * OK, * NO, * BAD, * SEARCH, * FETCH, etc.
  if (text.startsWith("*")) {
    const resp = text.slice(2, 80).trim();
    return `* ${resp}`;
  }

  // Untagged status: + ready for data continuation
  if (text.startsWith("+")) {
    return "Continue (ready for data)";
  }

  return text.slice(0, 80);
}


/**
 * Detect SSH version exchange and key exchange.
 */
export function summarizeSSH(payload: ArrayBuffer): string {
  const view = new Uint8Array(payload);
  // SSH starts with protocol version string: SSH-2.0-...
  if (view.length >= 4) {
    const prefix = String.fromCharCode(view[0], view[1], view[2], view[3]);
    if (prefix === "SSH-") {
      const line = firstLineAsText(payload, 256);
      return line || "SSH Version Exchange";
    }
  }
  // SSH binary protocol (after key exchange) - check packet types
  if (view.length >= 5) {
    const pktLen = (view[0] << 24) | (view[1] << 16) | (view[2] << 8) | view[3];
    if (pktLen > 1 && pktLen < 35000 && view.length >= 9) {
      const type = view[5];
      const sshTypes: Record<number, string> = {
        1:  "SSH_MSG_DISCONNECT",
        2:  "SSH_MSG_IGNORE",
        3:  "SSH_MSG_UNIMPLEMENTED",
        4:  "SSH_MSG_DEBUG",
        5:  "SSH_MSG_SERVICE_REQUEST",
        6:  "SSH_MSG_SERVICE_ACCEPT",
        20: "SSH_MSG_KEXINIT",
        21: "SSH_MSG_NEWKEYS",
        30: "SSH_MSG_KEXDH_INIT",
        31: "SSH_MSG_KEXDH_REPLY",
        32: "SSH_MSG_KEX_DH_GEX_GROUP",
        33: "SSH_MSG_KEX_DH_GEX_INIT",
        34: "SSH_MSG_KEX_DH_GEX_REPLY",
        50: "SSH_MSG_USERAUTH_REQUEST",
        51: "SSH_MSG_USERAUTH_FAILURE",
        52: "SSH_MSG_USERAUTH_SUCCESS",
        53: "SSH_MSG_USERAUTH_BANNER",
        60: "SSH_MSG_GLOBAL_REQUEST",
        61: "SSH_MSG_REQUEST_SUCCESS",
        62: "SSH_MSG_REQUEST_FAILURE",
        80: "SSH_MSG_CHANNEL_OPEN",
        81: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
        82: "SSH_MSG_CHANNEL_OPEN_FAILURE",
        83: "SSH_MSG_CHANNEL_WINDOW_ADJUST",
        84: "SSH_MSG_CHANNEL_DATA",
        85: "SSH_MSG_CHANNEL_EXTENDED_DATA",
        86: "SSH_MSG_CHANNEL_EOF",
        87: "SSH_MSG_CHANNEL_CLOSE",
        88: "SSH_MSG_CHANNEL_REQUEST",
        89: "SSH_MSG_CHANNEL_SUCCESS",
        90: "SSH_MSG_CHANNEL_FAILURE",
      };
      return sshTypes[type] ?? `Msg type=${type}`;
    }
  }
  return "SSH Encrypted Data";
}


/**
 * Summarize RDP (Remote Desktop Protocol) connection initiation.
 */
export function summarizeRDP(payload: ArrayBuffer): string {
  // RDP uses TPKT header (3 bytes) + TPDU, then RDP negotiation
  if (payload.byteLength < 7) return "";
  const view = new Uint8Array(payload);

  // Check TPKT (version 3)
  if (view[0] === 0x03) {
    const tpktLen = (view[2] << 8) | view[3];
    if (tpktLen < 7 || tpktLen > payload.byteLength) return "";

    // TPDU header: length(1) + type(1) + reserved(2)
    if (payload.byteLength >= 7) {
      const tpduType = view[5];
      const tpduMap: Record<number, string> = {
        0xe0: "Connection Request",
        0xd0: "Connection Confirm",
        0x80: "Disconnect Request",
        0xc0: "Data Transfer",
      };
      const tpduName = tpduMap[tpduType] ?? `TPDU 0x${tpduType.toString(16)}`;

      // For Connection Request / Confirm, look for RDP Negotiation
      if (tpduType === 0xe0 || tpduType === 0xd0) {
        // RDP Negotiation is typically in the first 12 bytes
        if (payload.byteLength >= 11) {
          const rdpType = view[8];
          const rdpLen = (view[10] << 8) | view[11];

          const rdpTypes: Record<number, string> = {
            1: "RDP Negotiation Request",
            2: "RDP Negotiation Response",
            3: "RDP Negotiation Failure",
          };
          const rdpName = rdpTypes[rdpType] ?? `RDP type ${rdpType}`;

          if (rdpType === 3 && rdpLen >= 4 && payload.byteLength >= 12) {
            const failCode = view[12];
            const failMap: Record<number, string> = {
              1: "SSL Required",
              2: "SSL Not Allowed",
              3: "SSL Cert Not Match",
              4: "Inconsistent Flags",
              5: "No Shared Protocol",
              6: "No Supported Method",
            };
            return `RDP ${rdpName}: ${failMap[failCode] ?? `Error ${failCode}`}`;
          }

          return `RDP ${rdpName} (${rdpName})`;
        }
      }
      return `RDP: ${tpduName}`;
    }
  }

  // Maybe RDP data — show first line if printable
  const text = firstLineAsText(payload, 60);
  return text ? `RDP: ${text}` : "";
}


/**
 * Summarize SIP — parse request/response line.
 */
export function summarizeSIP(payload: ArrayBuffer): string {
  const text = firstLineAsText(payload, 200);
  if (!text) return "SIP";
  // SIP/2.0 response or METHOD URI SIP/2.0 request
  if (text.startsWith("SIP/2.0")) {
    const parts = text.split(/\s+/);
    const code = parts[1];
    return `SIP Response ${code}${parts[2] ? ` ${parts[2]}` : ""}`;
  }
  const match = text.match(/^(\w+)\s+(sips?:[^\s]+)/i);
  if (match) {
    return `SIP ${match[1].toUpperCase()} ${match[2].slice(0, 50)}`;
  }
  return `SIP: ${text.slice(0, 80)}`;
}


/**
 * Summarize RTSP (Real-Time Streaming Protocol) payload.
 * RTSP is text-based (like HTTP): METHOD URL RTSP/1.0
 * Methods: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, etc.
 */
export function summarizeRTSP(payload: ArrayBuffer): string {
  if (payload.byteLength < 4) return "RTSP";
  const view = new Uint8Array(payload);

  // Try to decode as text
  let text = "";
  const maxLen = Math.min(view.length, 256);
  for (let i = 0; i < maxLen; i++) {
    const ch = view[i];
    if (ch === 0x0d || ch === 0x0a) break; // stop at CRLF
    if (ch < 0x20 || ch > 0x7e) { text = ""; break; } // not text
    text += String.fromCharCode(ch);
  }

  if (text.startsWith("RTSP/")) {
    // Response: RTSP/1.0 200 OK
    const codeMatch = text.match(/^RTSP\/[\d.]+\s+(\d{3})/);
    if (codeMatch) return `RTSP Response ${codeMatch[1]}`;
    return "RTSP Response";
  }

  // Request: METHOD url RTSP/1.0
  const reqMatch = text.match(/^(OPTIONS|DESCRIBE|ANNOUNCE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|SET_PARAMETER|REDIRECT|RECORD)\s+(\S+)/i);
  if (reqMatch) {
    return `RTSP ${reqMatch[1]} ${reqMatch[2]}`;
  }

  return "RTSP";
}
