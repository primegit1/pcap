import { Protocol } from "../../types/packets";
import type { Packet } from "../../types/packets";
import type { SecurityFinding } from "../../types/analysis";
import { Severity, FindingCategory } from "../../types/analysis";

import { nextFindingId as nextId } from "../findings";

/* ========== DHCP Binary Payload Parsing ========== */

const DHCP_MSG_DISCOVER = 1;
const DHCP_MSG_OFFER = 2;
const DHCP_MSG_REQUEST = 3;
const DHCP_MSG_DECLINE = 4;
const DHCP_MSG_ACK = 5;
const DHCP_MSG_NAK = 6;

const DHCP_MSG_NAMES: Record<number, string> = {
  1: "DISCOVER",
  2: "OFFER",
  3: "REQUEST",
  4: "DECLINE",
  5: "ACK",
  6: "NAK",
  7: "RELEASE",
  8: "INFORM",
};

interface DHCPParsed {
  msgType: number;
  msgTypeName: string;
  clientIp: string;
  requestedIp: string;
  serverId: string;
  clientId: string;
}

/**
 * Parse a DHCP packet from its binary payload.
 * BOOTP header (236 bytes) + magic cookie (4 bytes) + options.
 */
function parseDHCP(payload: ArrayBuffer): DHCPParsed | null {
  if (payload.byteLength < 240) return null;
  const view = new Uint8Array(payload);

  // Validate DHCP magic cookie at offset 236
  const magic = (view[236] << 24) | (view[237] << 16) | (view[238] << 8) | view[239];
  if (magic !== 0x63825363) return null;

  // yiaddr (client IP assigned) at offset 16-19
  const clientIp = `${view[16]}.${view[17]}.${view[18]}.${view[19]}`;

  // chaddr (client hardware address) at offset 28-43 (first 6 bytes are MAC)
  const hlen = view[2]; // hardware address length
  let clientId = "";
  if (hlen >= 6 && payload.byteLength >= 28 + 6) {
    clientId = Array.from(view.slice(28, 28 + Math.min(hlen, 16)))
      .map(b => b.toString(16).padStart(2, "0"))
      .join(":");
  }

  // Parse options starting at offset 240
  let msgType = 0;
  let requestedIp = "";
  let serverId = "";

  let pos = 240;
  while (pos + 1 < view.length) {
    const opt = view[pos];
    if (opt === 0xff) break; // End option
    if (opt === 0x00) { pos++; continue; } // Pad
    if (pos + 1 >= view.length) break;
    const len = view[pos + 1];
    if (pos + 2 + len > view.length) break;

    if (opt === 53 && len >= 1) {
      msgType = view[pos + 2];
    } else if (opt === 50 && len >= 4) {
      // Requested IP Address
      requestedIp = `${view[pos + 2]}.${view[pos + 3]}.${view[pos + 4]}.${view[pos + 5]}`;
    } else if (opt === 54 && len >= 4) {
      // Server Identifier
      serverId = `${view[pos + 2]}.${view[pos + 3]}.${view[pos + 4]}.${view[pos + 5]}`;
    }

    pos += 2 + len;
  }

  if (msgType === 0) return null; // Not a valid DHCP packet

  return {
    msgType,
    msgTypeName: DHCP_MSG_NAMES[msgType] ?? `Type ${msgType}`,
    clientIp: clientIp !== "0.0.0.0" ? clientIp : "",
    requestedIp,
    serverId,
    clientId,
  };
}

/* ========== Detection Rules ========== */

/**
 * Detect DHCP starvation attack: rapid DHCPREQUEST messages from same MAC
 * attempting to exhaust the IP address pool.
 */
export function detectDHCPStarvation(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track DHCP requests by client MAC
  const clientRequests = new Map<string, { count: number; firstUs: number; lastUs: number; ips: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DHCP) continue;
    if (!pkt.ethernet) continue;
    if (!pkt.appPayload) continue;

    const dhcp = parseDHCP(pkt.appPayload);
    if (!dhcp) continue;

    // DISCOVER and REQUEST both consume server resources
    if (dhcp.msgType !== DHCP_MSG_DISCOVER && dhcp.msgType !== DHCP_MSG_REQUEST) continue;

    const mac = pkt.ethernet.srcMac;
    const existing = clientRequests.get(mac) || { count: 0, firstUs: pkt.timestampUs, lastUs: pkt.timestampUs, ips: new Set<string>() };
    existing.count++;
    existing.lastUs = pkt.timestampUs;
    const ip = dhcp.requestedIp || dhcp.clientIp;
    if (ip) existing.ips.add(ip);
    clientRequests.set(mac, existing);
  }

  for (const [mac, data] of clientRequests) {
    const durationSec = (data.lastUs - data.firstUs) / 1_000_000;
    const requestsPerSec = data.count / (durationSec || 1);

    // High request rate indicates potential starvation attack
    if (data.count >= 10 && requestsPerSec > 5) {
      findings.push({
        id: nextId(),
        title: "DHCP Starvation Attack Pattern Observed",
        severity: Severity.High,
        description: `MAC ${mac} sent ${data.count} DHCP DISCOVER/REQUEST messages at ${requestsPerSec.toFixed(1)}/sec${data.ips.size > 1 ? `, requesting ${data.ips.size} different IPs` : ""}. Rapid DHCP requests may indicate a DHCP starvation attack, where an attacker exhausts the IP address pool by requesting multiple addresses. This is often combined with DHCP spoofing attacks to become the default gateway.`,
        recommendation: `1. Configure DHCP snooping on switches.
2. Set DHCP rate limits per MAC address.
3. Enable DHCP binding table to track authorized MAC-IP pairs.
4. Consider implementing 802.1X network access control.
5. Monitor for MAC addresses with multiple IP assignments.`,
        evidence: `DHCP messages: ${data.count}, Rate: ${requestsPerSec.toFixed(1)}/sec, Duration: ${durationSec.toFixed(2)}s, IPs requested: ${Array.from(data.ips).slice(0, 5).join(", ")}`,
        affectedIp: "network",
        category: FindingCategory.DHCP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect rogue DHCP servers by identifying multiple DHCP servers
 * responding with OFFER/ACK on the same network segment. A legitimate
 * network should typically have one or two authorized DHCP servers.
 */
export function detectDHCPRogueOffer(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Track all DHCP servers seen (by server identifier or source IP)
  const dhcpServers = new Map<string, { ip: string; offers: number; acks: number; offeredIps: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DHCP) continue;
    if (!pkt.ip) continue;
    if (!pkt.appPayload) continue;

    const dhcp = parseDHCP(pkt.appPayload);
    if (!dhcp) continue;

    if (dhcp.msgType === DHCP_MSG_OFFER || dhcp.msgType === DHCP_MSG_ACK) {
      // Use server identifier (option 54) if present, otherwise source IP
      const serverKey = dhcp.serverId || pkt.ip.srcIp;
      const existing = dhcpServers.get(serverKey) || { ip: pkt.ip.srcIp, offers: 0, acks: 0, offeredIps: new Set<string>() };

      if (dhcp.msgType === DHCP_MSG_OFFER) existing.offers++;
      if (dhcp.msgType === DHCP_MSG_ACK) existing.acks++;
      const offeredIp = dhcp.clientIp || dhcp.requestedIp;
      if (offeredIp) existing.offeredIps.add(offeredIp);

      dhcpServers.set(serverKey, existing);
    }
  }

  // If multiple DHCP servers are detected, flag as potential rogue
  if (dhcpServers.size >= 2) {
    const serverList = Array.from(dhcpServers.entries())
      .map(([id, data]) => `${id} (${data.offers} offers, ${data.acks} ACKs)`)
      .join("; ");

    findings.push({
      id: nextId(),
      title: "Multiple DHCP Servers Detected — Possible Rogue DHCP Server",
      severity: Severity.Critical,
      description: `${dhcpServers.size} different DHCP servers detected on the network: ${serverList}. Multiple DHCP servers may indicate a rogue DHCP server, which can assign malicious network settings to clients, redirect traffic to attacker-controlled systems, or cause IP conflicts. A rogue DHCP server is a common vector for man-in-the-middle attacks via gateway hijacking.`,
      recommendation: `1. Identify which DHCP server(s) are authorized in your network.
2. Investigate any unauthorized DHCP server immediately.
3. Implement DHCP snooping on switches to filter unauthorized OFFER/ACK messages.
4. Configure DHCP snooping trusted ports for authorized DHCP servers only.
5. Use 802.1X authentication for network access to prevent rogue devices.
6. Review DHCP logs for clients that received settings from the unauthorized server.`,
      evidence: `Servers: ${serverList}`,
      affectedIp: Array.from(dhcpServers.keys()).join(", "),
      category: FindingCategory.DHCP,
      timestamp: 0, // replaced with capture time by runAllRules
    });
  }

  return findings;
}

/**
 * Detect DHCP DECLINE messages — client rejecting offered IP.
 * This indicates the offered IP is already in use (IP conflict).
 */
export function detectDHCPDecline(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const declines: { clientMac: string; declinedIp: string; count: number }[] = [];

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DHCP) continue;
    if (!pkt.ethernet) continue;
    if (!pkt.appPayload) continue;

    const dhcp = parseDHCP(pkt.appPayload);
    if (!dhcp || dhcp.msgType !== DHCP_MSG_DECLINE) continue;

    const declinedIp = dhcp.requestedIp || "unknown";
    const clientMac = pkt.ethernet.srcMac;
    const existing = declines.find(d => d.clientMac === clientMac && d.declinedIp === declinedIp);
    if (existing) {
      existing.count++;
    } else {
      declines.push({ clientMac, declinedIp, count: 1 });
    }
  }

  for (const decline of declines) {
    if (decline.count >= 3) {
      findings.push({
        id: nextId(),
        title: "Multiple DHCP DECLINE Messages Detected",
        severity: Severity.Medium,
        description: `Client MAC ${decline.clientMac} declined DHCP offer for IP ${decline.declinedIp} ${decline.count} times. DHCP DECLINE messages indicate the client received the offered IP but found it already in use (IP conflict). Multiple declines may indicate IP conflict issues, a misconfigured DHCP scope, or an attacker intentionally declining to cause address pool exhaustion.`,
        recommendation: `1. Check for IP address conflicts on the network — the IP ${decline.declinedIp} may be statically assigned.
2. Review ARP table for duplicate IP detection.
3. Ensure your DHCP server isn't offering IPs that are statically assigned.
4. Exclude conflicting IPs from the DHCP scope.
5. Check if the DECLINE source is legitimate or malicious.`,
        evidence: `Client MAC: ${decline.clientMac}, Declined IP: ${decline.declinedIp}, Declines: ${decline.count}`,
        affectedIp: decline.declinedIp,
        category: FindingCategory.DHCP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}

/**
 * Detect DHCP NAK messages — server rejecting client requests.
 * Frequent NAKs can indicate configuration issues or attacks.
 */
export function detectDHCPNAK(packets: Packet[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const nakMap = new Map<string, { serverIp: string; count: number; clientMacs: Set<string> }>();

  for (const pkt of packets) {
    if (pkt.protocol !== Protocol.DHCP) continue;
    if (!pkt.ip) continue;
    if (!pkt.appPayload) continue;

    const dhcp = parseDHCP(pkt.appPayload);
    if (!dhcp || dhcp.msgType !== DHCP_MSG_NAK) continue;

    const serverKey = dhcp.serverId || pkt.ip.srcIp;
    const existing = nakMap.get(serverKey) || { serverIp: pkt.ip.srcIp, count: 0, clientMacs: new Set<string>() };
    existing.count++;
    if (pkt.ethernet) existing.clientMacs.add(pkt.ethernet.dstMac);
    nakMap.set(serverKey, existing);
  }

  for (const [serverId, data] of nakMap) {
    if (data.count >= 3) {
      findings.push({
        id: nextId(),
        title: "Multiple DHCP NAK Messages from Server",
        severity: Severity.Medium,
        description: `DHCP server ${serverId} (${data.serverIp}) sent ${data.count} NAK (Negative Acknowledgment) messages to ${data.clientMacs.size} client(s). NAKs indicate the server rejected IP assignment requests, typically because the requested IP is outside the server's scope, the lease has expired, or the client is on the wrong subnet. Frequent NAKs may indicate misconfiguration, a rogue client, or a network topology issue.`,
        recommendation: `1. Check DHCP server configuration and scope settings on ${serverId}.
2. Verify the server's address pools are correctly configured for all subnets.
3. Review server logs for specific NAK reason codes.
4. Check if clients are requesting IPs from the wrong subnet.
5. If NAKs target a specific client, investigate that client for misconfiguration or malicious activity.`,
        evidence: `Server: ${serverId}, NAK count: ${data.count}, affected clients: ${data.clientMacs.size}`,
        affectedIp: data.serverIp,
        category: FindingCategory.DHCP,
        timestamp: 0, // replaced with capture time by runAllRules
      });
    }
  }

  return findings;
}
