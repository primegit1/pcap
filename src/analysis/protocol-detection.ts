import type { Packet } from "../types/packets";
import { Protocol } from "../types/packets";
import type { ProtocolCount } from "../types/analysis";

/**
 * Calculate protocol distribution from decoded packets.
 */
export function calculateProtocolDistribution(
  packets: Packet[]
): ProtocolCount[] {
  const protoMap = new Map<string, { protocol: Protocol; packetCount: number; byteCount: number }>();

  for (const pkt of packets) {
    const proto = pkt.protocol;
    const key = proto;
    const existing = protoMap.get(key);
    if (existing) {
      existing.packetCount++;
      existing.byteCount += pkt.length;
    } else {
      protoMap.set(key, {
        protocol: proto,
        packetCount: 1,
        byteCount: pkt.length,
      });
    }
  }

  return Array.from(protoMap.values())
    .map(({ protocol, packetCount, byteCount }) => ({
      protocol,
      packetCount,
      byteCount,
      isOT: isOTProtocol(protocol),
    }))
    .sort((a, b) => b.packetCount - a.packetCount);
}

/**
 * Determine if a protocol is an OT/ICS protocol.
 */
export function isOTProtocol(protocol: Protocol): boolean {
  return ([
    Protocol.Modbus,
    Protocol.DNP3,
    Protocol.S7Comm,
    Protocol.EtherNetIP,
    Protocol.OPCDA,
    Protocol.OPCUA,
    Protocol.IEC104,
    Protocol.BACnet,
    Protocol.Profinet,
    Protocol.GeSRTP,
    Protocol.NiagaraFox,
    Protocol.HARTIP,
    Protocol.FFLR,
  ] as readonly Protocol[]).includes(protocol);
}
