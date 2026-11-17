/**
 * SSDP (Simple Service Discovery Protocol) parser.
 * SSDP is the discovery protocol of UPnP, using HTTP-like headers over UDP port 1900.
 *
 * Common message types:
 * - NOTIFY: Device/service announcement (ssdp:alive or ssdp:byebye)
 * - M-SEARCH: Client searching for devices/services
 * - Response: Device responding to M-SEARCH
 */

/** SSDP message type */
export type SSDPType = "NOTIFY" | "M-SEARCH" | "RESPONSE" | "UNKNOWN";

/** Parsed SSDP message fields */
export interface SSDPFields {
  type: SSDPType;
  /** Notification Type (NOTIFY messages) */
  nt?: string;
  /** Notification Sub-Type: ssdp:alive, ssdp:byebye, ssdp:update */
  nts?: string;
  /** Unique Service Name */
  usn?: string;
  /** Location URL of the device description XML */
  location?: string;
  /** Search Target (M-SEARCH messages) */
  st?: string;
  /** MAN header — "ssdp:discover" for M-SEARCH */
  man?: string;
  /** Max wait time in seconds for M-SEARCH responses */
  mx?: number;
  /** Server header */
  server?: string;
}

/**
 * Parse an SSDP message from raw payload.
 * SSDP uses HTTP-like headers over UDP.
 */
export function parseSSDP(payload: ArrayBuffer): SSDPFields | null {
  if (payload.byteLength < 4) return null;

  const text = new TextDecoder("utf-8").decode(payload);
  const lines = text.split("\r\n");

  if (lines.length === 0) return null;

  const requestLine = lines[0].trim();
  let type: SSDPType = "UNKNOWN";

  if (requestLine.startsWith("NOTIFY")) {
    type = "NOTIFY";
  } else if (requestLine.startsWith("M-SEARCH")) {
    type = "M-SEARCH";
  } else if (requestLine.startsWith("HTTP/")) {
    type = "RESPONSE";
  }

  const fields: SSDPFields = { type };
  const headers: Record<string, string> = {};

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const key = line.substring(0, colonIdx).trim().toLowerCase();
    const value = line.substring(colonIdx + 1).trim();
    headers[key] = value;
  }

  // Map standard SSDP headers
  if (headers["nt"]) fields.nt = headers["nt"];
  if (headers["nts"]) fields.nts = headers["nts"];
  if (headers["usn"]) fields.usn = headers["usn"];
  if (headers["location"]) fields.location = headers["location"];
  if (headers["st"]) fields.st = headers["st"];
  if (headers["man"]) fields.man = headers["man"];
  if (headers["server"]) fields.server = headers["server"];
  if (headers["mx"]) fields.mx = parseInt(headers["mx"], 10) || undefined;

  return fields;
}

/**
 * Produce a human-readable summary of an SSDP message.
 */
export function summarizeSSDP(payload: ArrayBuffer): string {
  const parsed = parseSSDP(payload);
  if (!parsed) return "SSDP";

  switch (parsed.type) {
    case "NOTIFY": {
      const nts = parsed.nts || "";
      const shortNts = nts.replace("ssdp:", "");
      const usn = parsed.usn ? ` [${truncateUSN(parsed.usn)}]` : "";
      const nt = parsed.nt ? ` -> ${truncateNT(parsed.nt)}` : "";
      return `SSDP NOTIFY (${shortNts})${usn}${nt}`;
    }
    case "M-SEARCH": {
      const st = parsed.st ? ` -> ${truncateNT(parsed.st)}` : "";
      const mx = parsed.mx ? ` (MX:${parsed.mx}s)` : "";
      return `SSDP M-SEARCH${st}${mx}`;
    }
    case "RESPONSE": {
      const st = parsed.st ? ` -> ${truncateNT(parsed.st)}` : "";
      if (parsed.location) {
        return `SSDP Response: ${extractHostFromURL(parsed.location)}${st}`;
      }
      return `SSDP Response${st}`;
    }
    default:
      return "SSDP";
  }
}

/**
 * Extract host from a URL for concise display.
 */
function extractHostFromURL(url: string): string {
  try {
    const m = url.match(/https?:\/\/([^/:]+)(?::\d+)?/);
    return m ? m[1] : url.substring(0, 40);
  } catch {
    return url.substring(0, 40);
  }
}

/**
 * Truncate a USN (Unique Service Name) for display.
 */
function truncateUSN(usn: string): string {
  // USN format: uuid:...::urn:...
  const parts = usn.split("::");
  if (parts.length >= 2) {
    const uuid = parts[0].replace("uuid:", "").substring(0, 8);
    return `${uuid}...${parts[parts.length - 1]}`;
  }
  if (usn.length > 32) return usn.substring(0, 29) + "...";
  return usn;
}

/**
 * Truncate an NT/ST (Notification Type / Search Target) for display.
 */
function truncateNT(nt: string): string {
  // Common prefixes: urn:schemas-upnp-org:service:..., upnp:rootdevice, ssdp:all
  const known: Record<string, string> = {
    "upnp:rootdevice": "Root Device",
    "ssdp:all": "All Services",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1": "IGD Device v1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2": "IGD Device v2",
    "urn:schemas-upnp-org:device:MediaRenderer:1": "Media Renderer",
    "urn:schemas-upnp-org:device:MediaServer:1": "Media Server",
    "urn:schemas-upnp-org:service:WANIPConnection:1": "WAN IP Conn",
    "urn:schemas-upnp-org:service:WANPPPConnection:1": "WAN PPP Conn",
    "urn:schemas-upnp-org:service:Layer3Forwarding:1": "Layer3 Fwd",
  };
  if (known[nt]) return known[nt];
  // Try to extract the last meaningful part after the final colon
  const lastColon = nt.lastIndexOf(":");
  if (lastColon >= 0) {
    const tail = nt.substring(lastColon + 1);
    return tail.length < nt.length ? `...${tail}` : nt;
  }
  if (nt.length > 40) return nt.substring(0, 37) + "...";
  return nt;
}
