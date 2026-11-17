import type { Packet, TCPHeader } from "../types/packets";
import { Protocol } from "../types/packets";
import type { FlowRecord, HostInfo, CommunicationPair } from "../types/analysis";

/** Internal accumulator; oriented as "first packet seen" until finalized. */
interface FlowAcc {
  proto: number;
  /** Endpoint A = sender of the first packet */
  aIp: string;
  aPort: number;
  bIp: string;
  bPort: number;
  appProtocol: Protocol;
  aPackets: number;
  bPackets: number;
  aBytes: number;
  bBytes: number;
  /** Which endpoint sent the first SYN without ACK ("a" | "b" | null) */
  synFrom: "a" | "b" | null;
  synAckSeen: boolean;
  finSeen: boolean;
  rstSeen: boolean;
  startTimeUs: number;
  endTimeUs: number;
}

/**
 * Group decoded packets into BIDIRECTIONAL flows (one record per conversation).
 *
 * The initiator becomes `srcIp/srcPort` and the responder `dstIp/dstPort`:
 *  - TCP: whoever sent the first SYN (without ACK).
 *  - otherwise the first-seen sender, unless it uses a well-known port (<1024) towards an
 *    ephemeral one, which means the capture started mid-conversation and the first packet was
 *    a reply.
 * Per-direction packet/byte counts are kept so rules can tell uploads from downloads.
 */
export function buildFlows(packets: Packet[]): FlowRecord[] {
  const flowMap = new Map<string, FlowAcc>();

  for (const pkt of packets) {
    if (!pkt.ip || !pkt.transport) continue;

    const srcIp = pkt.ip.srcIp;
    const dstIp = pkt.ip.dstIp;
    const proto = pkt.ip.protocol;

    let srcPort = 0;
    let dstPort = 0;
    let tcp: TCPHeader | null = null;
    if ("srcPort" in pkt.transport) {
      srcPort = pkt.transport.srcPort;
      dstPort = pkt.transport.dstPort;
      if ("syn" in pkt.transport) tcp = pkt.transport as TCPHeader;
    }

    // Canonical key: order the two endpoints so both directions map to the same flow.
    const srcFirst = srcIp < dstIp || (srcIp === dstIp && srcPort <= dstPort);
    const key = srcFirst
      ? `${proto}|${srcIp}|${srcPort}|${dstIp}|${dstPort}`
      : `${proto}|${dstIp}|${dstPort}|${srcIp}|${srcPort}`;

    let acc = flowMap.get(key);
    if (!acc) {
      acc = {
        proto,
        aIp: srcIp,
        aPort: srcPort,
        bIp: dstIp,
        bPort: dstPort,
        appProtocol: pkt.protocol,
        aPackets: 0,
        bPackets: 0,
        aBytes: 0,
        bBytes: 0,
        synFrom: null,
        synAckSeen: false,
        finSeen: false,
        rstSeen: false,
        startTimeUs: pkt.timestampUs,
        endTimeUs: pkt.timestampUs,
      };
      flowMap.set(key, acc);
    }

    const fromA = srcIp === acc.aIp && srcPort === acc.aPort;
    if (fromA) {
      acc.aPackets++;
      acc.aBytes += pkt.length;
    } else {
      acc.bPackets++;
      acc.bBytes += pkt.length;
    }

    if (acc.appProtocol === Protocol.Unknown && pkt.protocol !== Protocol.Unknown) {
      acc.appProtocol = pkt.protocol;
    }
    if (pkt.timestampUs < acc.startTimeUs) acc.startTimeUs = pkt.timestampUs;
    if (pkt.timestampUs > acc.endTimeUs) acc.endTimeUs = pkt.timestampUs;

    if (tcp) {
      if (tcp.syn && !tcp.ack && acc.synFrom === null) acc.synFrom = fromA ? "a" : "b";
      if (tcp.syn && tcp.ack) acc.synAckSeen = true;
      if (tcp.fin) acc.finSeen = true;
      if (tcp.rst) acc.rstSeen = true;
    }
  }

  const flows: FlowRecord[] = [];
  for (const acc of flowMap.values()) {
    let swap = false;
    if (acc.synFrom !== null) {
      swap = acc.synFrom === "b";
    } else if (acc.aPort > 0 && acc.aPort < 1024 && acc.bPort >= 1024) {
      swap = true; // first packet looks like a server reply
    }

    const i = swap
      ? { ip: acc.bIp, port: acc.bPort, packets: acc.bPackets, bytes: acc.bBytes }
      : { ip: acc.aIp, port: acc.aPort, packets: acc.aPackets, bytes: acc.aBytes };
    const r = swap
      ? { ip: acc.aIp, port: acc.aPort, packets: acc.aPackets, bytes: acc.aBytes }
      : { ip: acc.bIp, port: acc.bPort, packets: acc.bPackets, bytes: acc.bBytes };

    flows.push({
      id: `${acc.proto}|${i.ip}|${i.port}|${r.ip}|${r.port}`,
      srcIp: i.ip,
      dstIp: r.ip,
      srcPort: i.port,
      dstPort: r.port,
      ipProtocol: acc.proto,
      appProtocol: acc.appProtocol,
      packetCount: i.packets + r.packets,
      byteCount: i.bytes + r.bytes,
      initiatorPackets: i.packets,
      responderPackets: r.packets,
      initiatorBytes: i.bytes,
      responderBytes: r.bytes,
      synSeen: acc.synFrom !== null,
      synAckSeen: acc.synAckSeen,
      finSeen: acc.finSeen,
      rstSeen: acc.rstSeen,
      startTimeUs: acc.startTimeUs,
      endTimeUs: acc.endTimeUs,
    });
  }

  return flows;
}

/**
 * Build a map of unique hosts from flows.
 */
export function buildHosts(
  flows: FlowRecord[],
  packets: Packet[]
): Map<string, HostInfo> {
  const hostMap = new Map<string, HostInfo>();

  // Iterate flows to collect host data
  for (const flow of flows) {
    for (const ip of [flow.srcIp, flow.dstIp]) {
      const existing = hostMap.get(ip);
      if (existing) {
        existing.packetCount += flow.packetCount;
        existing.byteCount += flow.byteCount;
        existing.protocols.add(flow.appProtocol);
        existing.lastSeenUs = Math.max(existing.lastSeenUs, flow.endTimeUs);
        existing.firstSeenUs = Math.min(existing.firstSeenUs, flow.startTimeUs);
      } else {
        const isPrivate = isPrivateIP(ip);
        hostMap.set(ip, {
          ip,
          mac: "",
          packetCount: flow.packetCount,
          byteCount: flow.byteCount,
          protocols: new Set([flow.appProtocol]),
          firstSeenUs: flow.startTimeUs,
          lastSeenUs: flow.endTimeUs,
          isPrivate,
        });
      }
    }
  }

  // Try to add MAC addresses from packets
  for (const pkt of packets) {
    if (pkt.ethernet && pkt.ip) {
      const host = hostMap.get(pkt.ip.srcIp);
      if (host && !host.mac) {
        host.mac = pkt.ethernet.srcMac;
      }
      const dstHost = hostMap.get(pkt.ip.dstIp);
      if (dstHost && !dstHost.mac) {
        dstHost.mac = pkt.ethernet.dstMac;
      }
    }
  }

  return hostMap;
}

/**
 * Build communication pairs from flows.
 */
export function buildCommunicationPairs(flows: FlowRecord[]): CommunicationPair[] {
  const pairMap = new Map<string, CommunicationPair>();

  for (const flow of flows) {
    const key = `${flow.srcIp}-${flow.dstIp}-${flow.appProtocol}`;
    const existing = pairMap.get(key);
    if (existing) {
      existing.packetCount += flow.packetCount;
      existing.byteCount += flow.byteCount;
      existing.flows++;
    } else {
      pairMap.set(key, {
        srcIp: flow.srcIp,
        dstIp: flow.dstIp,
        protocol: flow.appProtocol,
        packetCount: flow.packetCount,
        byteCount: flow.byteCount,
        flows: 1,
      });
    }
  }

  return Array.from(pairMap.values());
}

/**
 * Check whether an IP address is in a private range.
 */
function isPrivateIP(ip: string): boolean {
  // Simple check for IPv4 private ranges
  // Using regex to avoid pulling in a full dependency
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("172.")) {
    const second = parseInt(ip.split(".")[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.startsWith("192.168.")) return true;
  if (ip.startsWith("127.")) return true;
  if (ip === "::1") return true;
  if (ip.startsWith("fe80:")) return true;
  if (ip.startsWith("fc") || ip.startsWith("fd")) return true; // Unique local address
  return false;
}

export { isPrivateIP };
