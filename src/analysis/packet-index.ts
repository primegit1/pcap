import type { Packet } from "../types/packets";
import { Protocol } from "../types/packets";

/**
 * Packet subsets built once per analysis so rules scan only what they need
 * instead of walking the full capture (~85 rules x N packets before).
 * Every subset preserves the original packet order.
 */
export interface PacketIndex {
  all: Packet[];
  byProtocol: Map<Protocol, Packet[]>;
  /** Packets with a TCP header */
  tcp: Packet[];
  /** Packets with a TCP or UDP header (i.e. have ports) */
  withPorts: Packet[];
  /** Packets whose detected protocol is ICMP */
  icmp: Packet[];
  arp: Packet[];
  igmp: Packet[];
}

export function buildPacketIndex(packets: Packet[]): PacketIndex {
  const byProtocol = new Map<Protocol, Packet[]>();
  const tcp: Packet[] = [];
  const withPorts: Packet[] = [];

  for (const pkt of packets) {
    let bucket = byProtocol.get(pkt.protocol);
    if (!bucket) {
      bucket = [];
      byProtocol.set(pkt.protocol, bucket);
    }
    bucket.push(pkt);

    const t = pkt.transport;
    if (t && "srcPort" in t) {
      withPorts.push(pkt);
      if ("syn" in t) tcp.push(pkt);
    }
  }

  return {
    all: packets,
    byProtocol,
    tcp,
    withPorts,
    icmp: byProtocol.get(Protocol.ICMP) ?? [],
    arp: byProtocol.get(Protocol.ARP) ?? [],
    igmp: byProtocol.get(Protocol.IGMP) ?? [],
  };
}
