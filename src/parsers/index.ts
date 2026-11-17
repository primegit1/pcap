import type { Packet, IPv4Header, IPv6Header, TCPHeader, UDPHeader } from "../types/packets";
import { Protocol } from "../types/packets";
import { parseEthernet } from "./ethernet";
import { parseIPv4 } from "./ipv4";
import { parseIPv6 } from "./ipv6";
import { parseTCP, formatTCPFlags } from "./tcp";
import { parseUDP } from "./udp";
import { parseICMP, getICMPTypeDescription } from "./icmp";
import { parseIGMP, getIGMPTypeDescription } from "./igmp";
import { parseARP, summarizeARP } from "./arp";
import { detectProtocol } from "./detect";
import { summarizePayload } from "./payload";

// Public API kept stable for existing importers.
export { PORT_PROTOCOL_MAP, detectProtocol } from "./detect";
export { summarizePayload } from "./payload";

/**
 * Parse a single packet from raw frame data.
 * Chains ethernet → IPv4/IPv6 → TCP/UDP/ICMP → protocol detection.
 */
export function parsePacket(
  data: ArrayBuffer,
  index: number,
  timestampUs: number
): Packet | null {
  try {
    const ethernet = parseEthernet(data);
    if (!ethernet) return null;

    const length = data.byteLength;
    let ip: IPv4Header | IPv6Header | null = null;
    let transport = null;
    let protocol: Protocol = Protocol.Unknown;
    let info = "";
    let appPayload: ArrayBuffer | null = null;
    let appPayloadSummary = "";

    // Layer 3: IP
    if (ethernet.etherType === 0x0800) {
      ip = parseIPv4(ethernet.payload, 0);
    } else if (ethernet.etherType === 0x86dd) {
      ip = parseIPv6(ethernet.payload, 0);
    } else if (ethernet.etherType === 0x0806) {
      // ARP
      const arp = parseARP(ethernet.payload, 0);
      if (arp) {
        protocol = Protocol.ARP;
        info = summarizeARP(ethernet.payload);
      } else {
        info = "ARP (malformed)";
      }
    }

    if (ip) {
      const pktBody = ethernet.payload;
      if (ip.protocol === 6) {
        // TCP
        transport = parseTCP(pktBody, ip.payloadOffset);
        if (transport) {
          const tcp = transport as TCPHeader;
          if (tcp.payloadLength > 0) {
            appPayload = pktBody.slice(tcp.payloadOffset, tcp.payloadOffset + tcp.payloadLength);
          }
          protocol = detectProtocol(
            ip.protocol,
            tcp.srcPort,
            tcp.dstPort,
            appPayload ? appPayload.slice(0, 64) : null
          );
          const flags = formatTCPFlags(tcp);
          info = `${tcp.srcPort} → ${tcp.dstPort} [${flags}]`;

          appPayloadSummary = summarizePayload(protocol, appPayload);
          if (appPayloadSummary) {
            info += ` | ${appPayloadSummary.split("\n")[0].trim()}`;
          }
        }
      } else if (ip.protocol === 17) {
        // UDP
        transport = parseUDP(pktBody, ip.payloadOffset);
        if (transport) {
          const udp = transport as UDPHeader;
          if (udp.payloadLength > 0) {
            appPayload = pktBody.slice(udp.payloadOffset, udp.payloadOffset + udp.payloadLength);
          }
          protocol = detectProtocol(
            ip.protocol,
            udp.srcPort,
            udp.dstPort,
            appPayload ? appPayload.slice(0, 64) : null
          );
          info = `${udp.srcPort} → ${udp.dstPort}`;

          appPayloadSummary = summarizePayload(protocol, appPayload);
          if (appPayloadSummary) {
            info += ` | ${appPayloadSummary}`;
          }
        }
      } else if (ip.protocol === 1) {
        transport = parseICMP(pktBody, ip.payloadOffset, false);
        if (transport) {
          const icmp = transport as import("../types/packets").ICMPHeader;
          protocol = Protocol.ICMP;
          info = getICMPTypeDescription(icmp.type, false);
          if (icmp.code > 0) info += ` (code ${icmp.code})`;
        }
      } else if (ip.protocol === 58) {
        transport = parseICMP(pktBody, ip.payloadOffset, true);
        if (transport) {
          const icmp = transport as import("../types/packets").ICMPHeader;
          protocol = Protocol.ICMP;
          info = getICMPTypeDescription(icmp.type, true);
          if (icmp.code > 0) info += ` (code ${icmp.code})`;
        }
      } else if (ip.protocol === 2) {
        // IGMP
        transport = parseIGMP(pktBody, ip.payloadOffset);
        if (transport) {
          const igmp = transport as import("../types/packets").IGMPHeader;
          protocol = Protocol.IGMP;
          info = getIGMPTypeDescription(igmp.type, igmp.version);
          if (igmp.groupAddress) {
            info += ` → ${igmp.groupAddress}`;
          }
        }
      } else if (ip.protocol === 47) {
        protocol = Protocol.GRE;
        if (ip.payloadLen > 0) {
          appPayload = pktBody.slice(ip.payloadOffset, ip.payloadOffset + ip.payloadLen);
        }
        info = `GRE Encapsulated Tunnel`;
        appPayloadSummary = summarizePayload(protocol, appPayload);
      } else if (ip.protocol === 89) {
        protocol = Protocol.OSPF;
        if (ip.payloadLen > 0) {
          appPayload = pktBody.slice(ip.payloadOffset, ip.payloadOffset + ip.payloadLen);
        }
        info = `OSPF Routing`;
        appPayloadSummary = summarizePayload(protocol, appPayload);
      } else if (ip.protocol === 88) {
        protocol = Protocol.EIGRP;
        if (ip.payloadLen > 0) {
          appPayload = pktBody.slice(ip.payloadOffset, ip.payloadOffset + ip.payloadLen);
        }
        info = `EIGRP Routing`;
        appPayloadSummary = summarizePayload(protocol, appPayload);
      } else if (ip.protocol === 112) {
        protocol = Protocol.VRRP;
        if (ip.payloadLen > 0) {
          appPayload = pktBody.slice(ip.payloadOffset, ip.payloadOffset + ip.payloadLen);
        }
        info = `VRRP Redundancy`;
        appPayloadSummary = summarizePayload(protocol, appPayload);
      }

      if (!info) {
        info = `IP proto ${ip.protocol}`;
      }
    } else {
      info = `EtherType 0x${ethernet.etherType.toString(16)}`;
    }

    // Drop the temporary payload copy: the raw frame already holds these bytes.
    const { payload: _discardedPayload, ...ethernetHeader } = ethernet;
    void _discardedPayload;

    return {
      index,
      timestampUs,
      raw: data,
      ethernet: ethernetHeader,
      ip,
      transport,
      protocol,
      info,
      length,
      appPayload,
      appPayloadSummary,
    };
  } catch {
    return null;
  }
}
